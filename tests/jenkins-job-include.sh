#!/bin/bash

# in case jenkins has -x set on, turn it off until we're ready
if [ -n "$JJ_DEBUG" ]
then set -e -x
else set -e +x
fi

VLIB="$(pwd)/vlib"
VENV="$(pwd)/venv"

if [ -e /etc/profile.d/kersplat.sh ]; then
    source /etc/profile.d/kersplat.sh
    pyenv local 2.7.14
    pyenv shell 2.7.14
fi

if [ -d "$VENV" -a -f "$VENV/bin/activate" ]
then source "$VENV/bin/activate" # probably linting or testing
fi

LOGPREFIX="$( cut -d- -f1 <<< "$(basename "$0")" )"
RESULT_FILE="${LOGPREFIX}-result.txt"
OUTPUT_FILE="${LOGPREFIX}-output.txt"
MANIFEST_FILE="${LOGPREFIX}-manifest.txt"

if [ -d "$VENV" -a -f "$VENV/bin/activate" ]
then source "$VENV/bin/activate"
fi

function clean_colors_output_file {
    sed -i -e 's/\x1b\[[0-9;]*m//g' "${1:-$OUTPUT_FILE}"
}

function error {
    local err_color=$'\e[0;31m'
    local err="$*"
    echo "ERROR${err:+: }${err_color}$err"
    return 1
}

function vecho {
    local VAR="$1"
    local VAL="$2"

    local var_color=$'\e[0;35m'
    local val_color=$'\e[1;35m'
    local rst_color=$'\e[m'

    if [ -z "$VAR" ]
    then return 0
    fi
    if [ -z "$VAL" ]
    then echo "${var_color}---- ${VAR}${rst_color}"; return 0
    fi

    if [[ "$VAL" =~ ^CMD: ]]; then
        VAL="$(${VAL:4} 2>&1)"
        if [ $? -gt 0 ]
        then val_color="$err_color"
        fi
    fi

    printf "$var_color%s $val_color%s$rst_color\n" "$VAR:" "$VAL"
    return 0
}

function relevant-files {
    local LHS="${1:-origin/$CHANGE_TARGET}"
    local RHS="${2:-origin/$BRANCH_NAME}"

    if [ -z "$1$CHANGE_TARGET" -o -z "$2$BRANCH_NAME" ]; then
        LHS="develop" # probably not in jenkins, use local shell's head
        RHS="HEAD"
    fi

    if [[ "$(git show -s --format='%s%n%b' "${LHS}..${RHS}" )" =~ LINT=FULL ]]
    then find hubblestack -name "*.py"
    else find hubblestack -name "*.py" -exec git diff --name-only "$LHS" "$RHS" {} +
    fi
}

function show_vars {
    vecho '$LOGPREFIX' "$LOGPREFIX"
    vecho which-python "CMD:which python"
    vecho which-pip    "CMD:which pip"
    vecho which-pylint "CMD:which pylint"
    vecho which-pytest "CMD:which pytest"
    if [ -d "$VENV" -a -f "$VENV/bin/activate" ]
    then vecho '$VENV' "$VENV"
    fi
}

if [ ! -d ./hubblestack ]; then
    error "something is wrong. there's no ./hubblestack"
    exit 1
fi

# # close stdout and stderr
# exec 1<&-
# exec 2<&-

# # open as a log
# exec 1<>"${LOGPREFIX}-console-output.txt"
# exec 2>&1

# 08:28:29 + printenv
# 08:28:29 BRANCH_NAME=PR-532
# 08:28:29 BUILD_DISPLAY_NAME=#49
# 08:28:29 BUILD_ID=49
# 08:28:29 BUILD_NUMBER=49
# 08:28:29 BUILD_TAG=jenkins-hubble-PR-532-49
# 08:28:29 BUILD_URL=https://jenkins.hubblestack.io/job/hubble/job/PR-532/49/
# 08:28:29 CHANGE_AUTHOR_DISPLAY_NAME=Paul Miller
# 08:28:29 CHANGE_AUTHOR_EMAIL=paul@jettero.pl
# 08:28:29 CHANGE_AUTHOR=jettero
# 08:28:29 CHANGE_BRANCH=dot-ci
# 08:28:29 CHANGE_FORK=jettero
# 08:28:29 CHANGE_ID=532
# 08:28:29 CHANGE_TARGET=develop
# 08:28:29 CHANGE_TITLE=experimental first pipeline jenkinsfile
# 08:28:29 CHANGE_URL=https://github.com/hubblestack/hubble/pull/532
# 08:28:29 CLASSPATH=
# 08:28:29 EXECUTOR_NUMBER=2
# 08:28:29 GIT_BRANCH=PR-532
# 08:28:29 GIT_COMMIT=61aa17089dd649094328a06568d37364102bd0fb
# 08:28:29 GIT_PREVIOUS_COMMIT=d075f51a236e3997e0cd6fd2b6319ef78d4e177f
# 08:28:29 GIT_PREVIOUS_SUCCESSFUL_COMMIT=c772f0458155e02105adc98caaed63997d06561c
# 08:28:29 GIT_URL=https://github.com/hubblestack/hubble.git
# 08:28:29 HOME=/root
# 08:28:29 HOSTNAME=1d1455ee5577
# 08:28:29 http_proxy=
# 08:28:29 https_proxy=
# 08:28:29 HUDSON_HOME=/opt/jenkins
# 08:28:29 HUDSON_SERVER_COOKIE=4b5d002888c49efa
# 08:28:29 HUDSON_URL=https://jenkins.hubblestack.io/
# 08:28:29 JENKINS_HOME=/opt/jenkins
# 08:28:29 JENKINS_NODE_COOKIE=99a8f854-3549-4bb0-8b88-dda7176d8445
# 08:28:29 JENKINS_SERVER_COOKIE=durable-3287eeb33f50c1e9a96c24be1a76bb55
# 08:28:29 JENKINS_URL=https://jenkins.hubblestack.io/
# 08:28:29 JOB_BASE_NAME=PR-532
# 08:28:29 JOB_DISPLAY_URL=https://jenkins.hubblestack.io/job/hubble/job/PR-532/display/redirect
# 08:28:29 JOB_NAME=hubble/PR-532
# 08:28:29 JOB_URL=https://jenkins.hubblestack.io/job/hubble/job/PR-532/
# 08:28:29 NODE_LABELS=docker jenkins-slave01
# 08:28:29 NODE_NAME=jenkins-slave01
# 08:28:29 PATH=/usr/local/pyenv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
# 08:28:29 PWD=/opt/jenkins/workspace/hubble_PR-532
# 08:28:29 PY_COLORS=1
# 08:28:29 PYENV_INSTALLER_URL=https://raw.githubusercontent.com/pyenv/pyenv-installer/master/bin/pyenv-installer
# 08:28:29 PYENV_ROOT=/usr/local/pyenv
# 08:28:29 PY_V=2.7.14
# 08:28:29 RUN_CHANGES_DISPLAY_URL=https://jenkins.hubblestack.io/job/hubble/job/PR-532/49/display/redirect?page=changes
# 08:28:29 RUN_DISPLAY_URL=https://jenkins.hubblestack.io/job/hubble/job/PR-532/49/display/redirect
# 08:28:29 SHLVL=2
# 08:28:29 STAGE_NAME=linting
# 08:28:29 TERM=xterm
# 08:28:29 _=/usr/bin/printenv
# 08:28:29 WORKSPACE=/opt/jenkins/workspace/hubble_PR-532
