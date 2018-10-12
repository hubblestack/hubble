crontab -l > currentcrons
echo "*/5 * * * * /bin/sh /etc/hubble/hubblectl.sh start" >> currentcrons
# restart hubble once every day at 0700 hours
echo "* 7 * * * /bin/sh /etc/hubble/hubblectl.sh restart" >> currentcrons
crontab currentcrons
rm currentcrons
service hubble start
