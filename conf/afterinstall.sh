crontab -l > currentcrons
# Try to start hubble every 5 mins. If hubble is already running, no action will be taken.
echo "*/5 * * * * /bin/sh /etc/hubble/hubblectl.sh start" >> currentcrons
# restart hubble once every day at 0700 hours. This is to handle scenarios where hubble goes into hang state
echo "* 7 * * * /bin/sh /etc/hubble/hubblectl.sh restart" >> currentcrons
crontab currentcrons
rm currentcrons
service hubble start
