#!/bin/sh

##
## Script to start/stop/restart hubble
## To be executed using cron job. 
##

dir="/etc/hubble"
cmd="/opt/hubble/hubble -d"

name="hubble"
pid_file="/var/run/$name.pid"
log_file="/var/log/hubble"

get_pid() {
    cat "$pid_file"
}

is_running() {
    [ -f "$pid_file" ] && ps `get_pid` > /dev/null 2>&1
}

case "$1" in
    start)
    if is_running; then
        echo "Already started"
    else
        echo "Starting $name"
        cd "$dir"
        $cmd
        sleep 0.1
        if ! is_running; then
            echo "Unable to start, see $log_file"
            exit 1
        fi
    fi
    ;;
    stop)
    if is_running; then
        echo -n "Stopping $name..."
        kill `get_pid`
        sleep 0.1
        for i in {1..10}
        do
            if ! is_running; then
                break
            fi

            echo -n "."
            sleep 1
        done
        echo

        if is_running; then
            echo "Not stopped; may still be shutting down or shutdown may have failed"
            exit 1
        else
            echo "Stopped"
        fi
    else
        echo "Not running"
    fi
    ;;
    restart)
    $0 stop
    if is_running; then
        echo "Unable to stop, will not attempt to start"
        exit 1
    fi
    $0 start
    ;;
    *)
    echo "Usage: $0 {start|stop|restart}"
    exit 1
    ;;
esac

exit 0