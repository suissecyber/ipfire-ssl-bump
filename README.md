# Squid SSL-Bump Configuration for IPFire 2.29

## Overview
This project provides a custom script to configure and enhance the Squid proxy server on **IPFire 2.29**. 
The script integrates SSL-Bump functionality, allowing HTTPS inspection, dynamic SSL certificate generation, 
and seamless network redirection within the IPFire environment.

## Features
- **Automatic Network Configuration**:
  - Detects the `green0` interface and calculates IP, subnet, and CIDR.
- **Squid Proxy Setup**:
  - Installs Squid binaries with SSL-Bump enabled.
  - Configures ACLs, ports, and custom proxy settings.
- **SSL Management**:
  - Automates the generation and management of SSL certificates in `/etc/squid/ssl_cert/`.
  - Fixes `ssl_db` initialization issues.
- **Firewall Integration**:
  - Updates `firewall.local` with custom iptables rules for secure traffic redirection.
- **Debugging Tools**:
  - Includes debug options to monitor and troubleshoot Squid behavior.

## Requirements
- **IPFire Version**: 2.29
- **Dependencies**:
  - OpenSSL (`openssl`)
  - Squid proxy server binaries compatible with IPFire
  - Root privileges for installation and configuration

## Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/suissecyber/ipfire-ssl-bump.git
   cd ipfire-ssl-bump
   ```

2. Make the script executable:
   ```bash
   chmod +x install.sh
   ```

3. Run the script:
   ```bash
   sudo ./install.sh
   ```

## Script Workflow
1. **Network Configuration**:
   - Identifies and configures the Green interface (`green0`).
   - Calculates the network subnet and mask.

2. **Squid Proxy Setup**:
   - Copies the Squid binary to `/usr/sbin/` and enables execution.
   - Configures Squid to support SSL-Bump and dynamic certificate generation.

3. **SSL Certificate Management**:
   - Creates the `/etc/squid/ssl_cert/` directory if missing.
   - Generates a root certificate (`squid.pem`) if not already present.

4. **Firewall Rules**:
   - Adds or updates iptables rules in `firewall.local` for HTTPS inspection and proxy traffic redirection.

5. **Debugging**:
   - Appends Squid debug options and logs for troubleshooting.

## Testing
To verify that Squid is running and inspect its behavior, you can monitor its logs:

- **Cache Log**: Inspect Squid's operational status and errors:
  ```bash
  tail -f /var/log/squid/cache.log
  ```

- **Access Log**: View detailed traffic information, including CONNECT and GET requests:
  ```bash
  tail -f /var/log/squid/access.log
  ```

## Usage
- Access the proxy server using the configured port (e.g., `4128` for SSL-Bump).

## Known Issues and Fixes
- **`ssl_db` Initialization Error**:
  - The script includes commands to resolve the `ssl_db` initialization issue.

- **Permission Errors**:
  - Ensure the script is executed with root privileges.

## Contributing
Feel free to fork this repository, open issues, or submit pull requests to improve the script or add new features.

## License
This project is licensed under the [GPL-3.0 License](https://www.gnu.org/licenses/gpl-3.0.en.html).
