#!/bin/bash

###### IP AND MASK

# Name of the Green interface
GREEN_INTERFACE="green0"  # Change if necessary

# Retrieve the IP and subnet mask of the Green interface
GREEN_IP_WITH_CIDR=$(ip -o -4 addr show dev "$GREEN_INTERFACE" | awk '{print $4}')

if [ -z "$GREEN_IP_WITH_CIDR" ]; then
    echo "Error: Unable to determine the IP address for the Green interface ($GREEN_INTERFACE)."
    exit 1
fi

# Extract the IP address and subnet mask (CIDR)
GREEN_IP=$(echo "$GREEN_IP_WITH_CIDR" | cut -d'/' -f1)
GREEN_CIDR=$(echo "$GREEN_IP_WITH_CIDR" | cut -d'/' -f2)

# Convert the IP address to decimal format
IFS='.' read -r ip1 ip2 ip3 ip4 <<< "$GREEN_IP"
IP_DECIMAL=$((ip1*256*256*256 + ip2*256*256 + ip3*256 + ip4))

# Calculate the network mask in decimal format
MASK=$((0xFFFFFFFF << (32 - GREEN_CIDR) & 0xFFFFFFFF))

# Calculate the network by applying AND between the IP and the mask
NETWORK=$((IP_DECIMAL & MASK))

# Convert the network back to IP format
NETWORK_IP1=$(( (NETWORK >> 24) & 0xFF ))
NETWORK_IP2=$(( (NETWORK >> 16) & 0xFF ))
NETWORK_IP3=$(( (NETWORK >> 8) & 0xFF ))
NETWORK_IP4=$(( NETWORK & 0xFF ))

# Create the final subnet
NETWORK_SUBNET="$NETWORK_IP1.$NETWORK_IP2.$NETWORK_IP3.0/$GREEN_CIDR"

###### SQUID CACHE SSL BUMP

# Stop the process
/etc/init.d/squid stop

# Define the source and destination file paths
SOURCE_FILE="binary/squid_cache_610_x86_64"
DEST_FILE="/usr/sbin/squid"

# Check if the source file exists
if [ -f "$SOURCE_FILE" ]; then
    echo "Source file found: $SOURCE_FILE"

    # Copy the file to the destination and rename it as "squid"
    sudo cp "$SOURCE_FILE" "$DEST_FILE"

    # Check if the copy was successful
    if [ $? -eq 0 ]; then
        echo "File successfully copied to $DEST_FILE"

        # Grant execution permissions to the file
        sudo chmod +x "$DEST_FILE"

        if [ $? -eq 0 ]; then
            echo "Execution permissions successfully assigned to $DEST_FILE"
        else
            echo "Error assigning execution permissions"
        fi
    else
        echo "Error copying the file"
    fi
else
    echo "Source file not found: $SOURCE_FILE"
fi

# Define the source and destination file paths for the second file
SOURCE_FILE="binary/security_file_certgen_x86_64"
DEST_FILE="/usr/lib/squid/security_file_certgen"

# Check if the source file exists
if [ -f "$SOURCE_FILE" ]; then
    echo "Source file found: $SOURCE_FILE"

    # Copy the file to the destination and rename it as "security_file_certgen"
    sudo cp "$SOURCE_FILE" "$DEST_FILE"

    # Check if the copy was successful
    if [ $? -eq 0 ]; then
        echo "File successfully copied to $DEST_FILE"

        # Grant execution permissions to the file
        sudo chmod +x "$DEST_FILE"

        if [ $? -eq 0 ]; then
            echo "Execution permissions successfully assigned to $DEST_FILE"
        else
            echo "Error assigning execution permissions"
        fi
    else
        echo "Error copying the file"
    fi
else
    echo "Source file not found: $SOURCE_FILE"
fi

# Create the symbolic link /usr/lib/libcrypt.so.2 to /usr/lib/libcrypt.so.1
echo "Creating the symbolic link /usr/lib/libcrypt.so.2 -> /usr/lib/libcrypt.so.1"

# Check if the symbolic link already exists
if [ ! -L "/usr/lib/libcrypt.so.2" ]; then
    sudo ln -s /usr/lib/libcrypt.so.1 /usr/lib/libcrypt.so.2
    if [ $? -eq 0 ]; then
        echo "Symbolic link successfully created."
    else
        echo "Error creating the symbolic link."
    fi
else
    echo "The symbolic link /usr/lib/libcrypt.so.2 already exists."
fi

###### ACLS_INCLUDE_FILES

# Path to the file to be modified
FILE_PATH="/var/ipfire/proxy/advanced/acls/include.acl"

# Content to append
BLOCK_TO_ADD=$(cat << EOF
#logformat custom %>a %ui %un [%tl] "%rm %>ru HTTP/%rv" %>Hs %<st %>h %Ss/%03>Hs %rm
#access_log /var/log/squid/access.log custom

http_port $GREEN_IP:4128 ssl-bump generate-host-certificates=on dynamic_cert_mem_cache_size=4MB cert=/etc/squid/ssl_cert/squid.pem key=/etc/squid/ssl_cert/squid.pem

acl SSL_ports port 443
acl CONNECT method CONNECT

http_access allow CONNECT SSL_ports
http_access allow all

ssl_bump server-first all

sslcrtd_program /usr/lib/squid/security_file_certgen -s /var/cache/squid/ssl_db -M 4MB
sslcrtd_children 1000 startup=50 idle=20

#cache_dir ufs /var/cache/squid 1000 16 256

sslproxy_cert_error allow all

# url_rewrite_extras
url_rewrite_extras "%>a/%>A %un %>rm myip=%la myport=%lp"

# LIMIT PARTIAL RESPONSES
range_offset_limit -1

#follow_x_forwarded_for allow all

# DEBUG
debug_options ALL,1
EOF
)

# Check if the block is already present in the file
if grep -qF "ssl-bump generate-host-certificates=on" "$FILE_PATH"; then
    echo "The block is already present in the file. No changes needed."
else
    # Append the block to the file
    echo "$BLOCK_TO_ADD" >> "$FILE_PATH"
    echo "The block has been successfully added."
fi

###### FIREWALL RULES

# Variable names with _PATH suffix
FILE_PATH="/etc/sysconfig/firewall.local"
BACKUP_PATH="$FILE_PATH.bak"

# Check if NETWORK_SUBNET is defined
if [ -z "$NETWORK_SUBNET" ]; then
    echo "Error: The NETWORK_SUBNET variable is not defined."
    exit 1
fi

# Create a backup
cp "$FILE_PATH" "$BACKUP_PATH"

# Verify if the backup copy was successful
if [[ ! -f "$BACKUP_PATH" ]]; then
    echo "Error: Unable to create the backup of $FILE_PATH."
    exit 1
fi

echo "Backup successfully created: $BACKUP_PATH"

# Define iptables rules in an array. Proper use of $NETWORK_SUBNET
RULES=(
"iptables -t nat -A PREROUTING -p tcp --dport 8443 -j REDIRECT --to-port 800"
"iptables -t nat -D PREROUTING -p tcp --dport 8443 -j REDIRECT --to-port 800"
"iptables -A FORWARD -p tcp -s $NETWORK_SUBNET -d 127.0.0.1 --dport 8443 -j ACCEPT"
"iptables -A FORWARD -p tcp -s $NETWORK_SUBNET -d 127.0.0.1 --dport 4128 -j ACCEPT"
"iptables -A FORWARD -p tcp -s $NETWORK_SUBNET -d 127.0.0.1 --dport 3128 -j ACCEPT"
"iptables -A FORWARD -p tcp -d 127.0.0.1 --dport 4128 -j ACCEPT"
"iptables -A FORWARD -p tcp -d 127.0.0.1 --dport 3128 -j ACCEPT"
"iptables -A INPUT -p tcp --dport 443 -j ACCEPT  # SSL"
"iptables -t nat -A PREROUTING -p tcp --dport 8443 -j REDIRECT --to-port 4128"
"iptables -t nat -A PREROUTING -p tcp --dport 8443 -j REDIRECT --to-port 800"
"iptables -A INPUT -p tcp --dport 4128 -j ACCEPT  # Squid SSL-bump"
"iptables -A INPUT -p tcp --dport 3128 -j ACCEPT  # Squid transparent proxy"
"iptables -A INPUT -p tcp --dport 800 -j ACCEPT   # Squid HTTP"
"iptables -A INPUT -p tcp --dport 8443 -j ACCEPT  # Proxy"
)

# Iterate over the rules and check if they are already present, operating directly on the file
for RULE in "${RULES[@]}"; do
    if ! grep -q "$RULE" "$FILE_PATH"; then  # Check if the rule is NOT present
        # Find the line with the comment and add the rule after it using sed -i
        sed -i "/## add your 'start' rules here/a\\$RULE" "$FILE_PATH"
        echo "Rule added: $RULE"
    else
        echo "Rule already present: $RULE"
    fi
done

echo "Update of $FILE_PATH completed."

# Restart the firewall
echo "Restarting the firewall..."
/etc/init.d/firewall restart

###### SSL CERT

# Paths
SSL_CERT_DIR="/etc/squid/ssl_cert"
SSL_CERT_FILE="$SSL_CERT_DIR/squid.pem"
CACHE_DIR="/var/cache/squid/ssl_db"

# Check and create the ssl_cert folder if it does not exist
if [ ! -d "$SSL_CERT_DIR" ]; then
    echo "The directory $SSL_CERT_DIR does not exist. Creating it..."
    mkdir -p "$SSL_CERT_DIR"
    chown squid:squid "$SSL_CERT_DIR"
    chmod 755 "$SSL_CERT_DIR"
    echo "The directory $SSL_CERT_DIR has been created."
fi

# Generate the SSL certificate if it does not exist
if [ ! -f "$SSL_CERT_FILE" ]; then
    echo "The file $SSL_CERT_FILE does not exist. Generating it..."
    openssl req -new -newkey rsa:2048 -sha256 -days 365 -nodes \
        -x509 -keyout "$SSL_CERT_FILE" -out "$SSL_CERT_FILE"
    chown squid:squid "$SSL_CERT_FILE"
    chmod 600 "$SSL_CERT_FILE"
    echo "The certificate $SSL_CERT_FILE has been generated."
else
    echo "The certificate $SSL_CERT_FILE already exists. No action required."
fi

# Generate a squid.cer file from the certificate
OUTPUT_FILE="squid_ipfire_$NETWORK.cer"
echo "Creating the file $OUTPUT_FILE..."
openssl x509 -in "$SSL_CERT_FILE" -out "$OUTPUT_FILE" -outform PEM
if [ -f "$OUTPUT_FILE" ]; then
    echo "The file $OUTPUT_FILE has been successfully created."
else
    echo "Error creating the file $OUTPUT_FILE."
fi

### FIX FATAL ERROR
sudo rm -rf /var/cache/squid/ssl_db/
### GENERATE SQUID FOLDER
mkdir -p /var/cache/squid/
chown -R squid:squid /var/cache/squid/
chmod -R 700 /var/cache/squid/

sudo /usr/lib/squid/security_file_certgen -c -s /var/cache/squid/ssl_db -M 4MB

# Start Squid
/etc/init.d/squid start