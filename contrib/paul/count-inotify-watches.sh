#!/usr/bin/env bash

# NOTE: this doesn't actually work!
# it's a common theme on stackoverflow and the like to do something like this
# the pyinotify has only one or two filehandles for all the watches, so you get
# a '2' for hubblestack, despite it watching potentially thousands of things.

function count_inotify_pids() {
    sudo find /proc/ -path \*/fd/\* -lname anon_inode:inotify 2>/dev/null \
        | cut -d/ -f3 | sort -n | uniq -c | sort -n
}

function populate_counts() {
    while read X; do
        c="$( sed -e 's/  *[0-9][0-9]*$//' <<< "$X" )"
        p="$( sed -e 's/.*  *//' <<< "$X" )"

        printf '%10d %s\n' $c "$( ps --no-headers -p $p -o pid -o cmd )"
    done
}

count_inotify_pids | populate_counts
