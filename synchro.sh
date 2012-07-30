#!/bin/bash

DOMAIN="XXX.fr"

HOSTS=("blah" "titi" "toto" "tata")

HONEYPOTS_DIR="/opt"
DIONAEA_DIR="dionaea"
KIPPO_DIR="kippo-0.5"
#GLASTOPF_DIR="glastopf/trunk"
LOCAL_DIR="/srv/HoneyPi"

#DIRECTORIES=("$DIONAEA_DIR/var/dionaea" "$KIPPO_DIR/dl" "$KIPPO_DIR/data" "$KIPPO_DIR/log" "$GLASTOPF_DIR/log" "$GLASTOPF_DIR/files" "$GLASTOPF_DIR/db")

RSYNC_CMD='rsync -u -r --rsh "ssh -p 2222" ' 


if [ ! -d $LOCAL_DIR ]; then
  echo "Create $LOCAL_DIR with appropriate rights before run this script"
  exit
fi

for host in ${HOSTS[*]}
do
  echo "Synchronizing : $host.$DOMAIN"

  echo "  - Dionaea ..."
  if [ ! -d $LOCAL_DIR"/dionaea" ]; then
    mkdir -p $LOCAL_DIR/$host/"dionaea"
  fi
  CMD="$RSYNC_CMD --exclude='bistreams/' --exclude='wwwroot/' dionaea@$host.$DOMAIN:$HONEYPOTS_DIR/dionaea/var/dionaea/ $LOCAL_DIR/$host/dionaea"
  eval $CMD

  echo "  - Kippo ..."
  for dir in "$KIPPO_DIR/dl" "$KIPPO_DIR/data" "$KIPPO_DIR/log"
  do
    if [ ! -d $LOCAL_DIR/$dir ]; then
      mkdir -p $LOCAL_DIR/$host/$dir
    fi
    CMD="$RSYNC_CMD kippo@$host.$DOMAIN:$HONEYPOTS_DIR/$dir/ $LOCAL_DIR/$host/$dir"
    eval $CMD
  done

done
