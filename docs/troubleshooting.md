# Troubleshooting

Common issues and solutions for Keywarden.

## Startup Issues

### "Failed to initialize database"

**Cause**: SQLite database file cannot be created or accessed.

**Solutions**:
- Check that the `/data` directory exists and is writable
- Verify the `KEYWARDEN_DB_PATH` environment variable
- In Docker: ensure the volume is correctly mounted and the `keywarden` user has write access

### "Failed to create directory"

**Cause**: Data directories (`/data`, `/data/keys`, `/data/master`) cannot be created.

**Solutions**:
- Check filesystem permissions
- In Docker: the container runs as user `keywarden` — ensure the volume has correct ownership

### Initial Password Not Showing

**Cause**: The initial owner password is only printed on the **first startup** when no users exist.

**Solutions**:
- Check the very first startup logs: `docker compose logs keywarden`
- Reset the password via CLI command (no restart needed):
  ```bash
  docker exec -it keywarden ./keywarden reset-password --username admin
  ```
- If MFA is also lost, add `--reset-mfa`:
  ```bash
  docker exec -it keywarden ./keywarden reset-password --username admin --reset-mfa
  ```

## Login Issues

### "Invalid username or password"

- Verify the username (case-sensitive)
- Check for typos in the password
- If this is the initial login, find the auto-generated password in the startup logs

### "Account is temporarily locked"

**Cause**: Too many failed login attempts.

**Solutions**:
- Wait for the lockout period to expire (default: 15 minutes)
- Ask an administrator to unlock the account from the user management page
- If you're the only owner: reset your password via CLI (this also clears lockout):
  ```bash
  docker exec -it keywarden ./keywarden reset-password --username admin
  ```

### MFA Code Invalid

- Verify your authenticator app has the correct time (TOTP is time-based)
- Allow ±30 seconds of clock skew
- If you lost your MFA device, an admin with database access will need to manually disable MFA

### "Forbidden – invalid or missing CSRF token"

**Cause**: CSRF token mismatch. This can happen if:
- Your session expired and you submitted a form on a stale page
- Cookies are blocked by your browser
- A proxy is stripping or modifying cookies

**Solutions**:
- Refresh the page and try again
- Clear your browser cookies for the Keywarden domain
- Ensure cookies are not being blocked

## SSH Deployment Issues

### "System master key not available"

**Cause**: The system master key is missing or corrupted in the settings table.

**Solutions**:
- Check the startup logs for the master key output
- Navigate to Admin Settings and view the master key
- If corrupted, regenerate the master key (owner only)

### "Connection failed" / "Cannot reach server"

**Cause**: Keywarden cannot establish a TCP connection to the target server.

**Solutions**:
- Verify the server hostname and port
- Use the **Connection Test** feature to check TCP connectivity
- Ensure the Keywarden container can reach the server's network
- Check firewall rules on both sides

### "SSH authentication failed"

**Cause**: The system master key is not authorized on the target server.

**Solutions**:
1. Get the master public key from Admin Settings or startup logs
2. Add it to the target server:
   ```bash
   echo "<master-public-key>" >> /root/.ssh/authorized_keys
   chmod 600 /root/.ssh/authorized_keys
   ```
3. Ensure the server's SSH daemon accepts public key authentication
4. Use the **Auth Test** feature to verify
5. If using a non-root admin user on the target server, ensure that user has permissions to manage `authorized_keys` for other users

### "Failed to create system user"

**Cause**: The `useradd` command failed on the target server.

**Solutions**:
- Verify the server's admin user has sufficient privileges (root or sudo)
- Check if the username conflicts with an existing user
- Review the server's `/var/log/auth.log` for details

### "Failed to deploy key for user"

**Cause**: Key deployment to a specific system user failed.

**Solutions**:
- Verify the system user exists (or enable "Create User" in the assignment)
- Check directory permissions on the target server
- Ensure the admin user can write to other users' `.ssh` directories

## Email Issues

### "Email is not configured"

**Cause**: `KEYWARDEN_SMTP_HOST` is not set.

**Solution**: Configure SMTP settings in the `.env` file. See [Email Configuration](email.md).

### SMTP Connection Errors

- Verify the SMTP host, port, and credentials
- Check if the Docker container can reach the SMTP server
- Try different TLS settings (`KEYWARDEN_SMTP_TLS=true/false`)
- For port 465, ensure implicit TLS is supported by the server
- Check if the SMTP server requires app-specific passwords

### Invitation Emails Not Arriving

- Verify the recipient's email address
- Check spam/junk folders
- Review application logs for SMTP errors (`KEYWARDEN_LOG_LEVEL=DEBUG`)
- Verify `KEYWARDEN_BASE_URL` is set correctly (needed for the invitation link)
- Send a test email from Admin Settings to verify SMTP works

## Backup Issues

### "Failed to decrypt backup"

**Cause**: Wrong backup password.

**Solution**: Use the exact password that was provided during backup export.

### "Failed to parse backup"

**Cause**: The backup file is corrupt or not a valid `.kwbak` file.

**Solution**: Ensure the file was not modified or corrupted during transfer.

### SSH Keys Not Working After Restore

**Cause**: The `KEYWARDEN_ENCRYPTION_KEY` in the current environment doesn't match the one used when the backup was created.

**Solution**: Set `KEYWARDEN_ENCRYPTION_KEY` to the same value that was in use when the backup was created.

## Performance

### Slow Page Loads

- Check the log level — `TRACE` and `DEBUG` can be verbose
- SQLite WAL mode is enabled by default for better concurrent read performance
- The in-memory session store scales well for typical deployments

### High Memory Usage

- Sessions are stored in memory — many active sessions increase memory
- The session cleanup goroutine runs every minute to remove expired sessions
- Avatar images are served from disk, not stored in memory

## Logs

### Viewing Logs

```bash
# Docker
docker compose logs keywarden
docker compose logs -f keywarden  # follow

# Log levels
KEYWARDEN_LOG_LEVEL=DEBUG  # more detail
KEYWARDEN_LOG_LEVEL=TRACE  # maximum verbosity
```

### Log Levels

| Level | Output |
|---|---|
| `ERROR` | Only errors |
| `WARN` | Errors + warnings |
| `INFO` | Errors + warnings + informational (default) |
| `DEBUG` | All of the above + debug details |
| `TRACE` | Maximum verbosity, including request/response details |

### Request Logging

Every HTTP request is logged with:
- Method, path, status code
- Response time
- Client IP address
- Username (if authenticated)

---

## Still Need Help?

If your issue isn't covered here, join the community Matrix chat to ask for help:

➡️ [#keywarden:techniverse.net](https://matrix.to/#/#keywarden:techniverse.net)
