echo "*/5 * * * * root /etc/init.d/hubble start" >> hubble-autostart
# restart hubble once every day at 0700 hours
echo "* 7 * * * root /etc/init.d/hubble restart" >> hubble-autostart
mv hubble-autostart /etc/cron.d/
service hubble start
