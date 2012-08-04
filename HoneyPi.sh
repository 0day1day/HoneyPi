#!/bin/bash

HONEYPI_DIR='/srv/HoneyPi'
DATE=`date -u  +"%F"`
OUTPUT_FILE="/tmp/HoneyPi_$DATE"
DESTINATION_EMAIL="XXX@gmail.com"

# Symchronize all honeypots
./synchro.sh

HONEYPOTS=`ls $HONEYPI_DIR`

echo "Generating HoneyPi reports ..."

for f in $HONEYPOTS
do
  if [ "$f" != "HoneyPi" ]; then
    echo "$f ..."
    echo "########################" >> $OUTPUT_FILE
    echo "$f ..." >> $OUTPUT_FILE
    echo "    KIPPO stats ..." >> $OUTPUT_FILE
    ./kippo.py "$HONEYPI_DIR/$f/kippo-0.5/" "./ext/GeoIP.dat" &>> $OUTPUT_FILE

    echo -e '\n\n' >> $OUTPUT_FILE
    echo "    BINARIES stats ..." >> $OUTPUT_FILE
    ./VirusTotalUploader.py -d 1 -y -r "$HONEYPI_DIR/$f/dionaea/binaries/" &>> $OUTPUT_FILE
    echo -e '\n\n' >> $OUTPUT_FILE


    echo "    DIONAEA stats ..." >> $OUTPUT_FILE
    ./Dionaea.py "$HONEYPI_DIR/$f/dionaea/logsql.sqlite" "./ext/GeoIP.dat" &>> $OUTPUT_FILE
    echo -e '\n\n\n\n' >> $OUTPUT_FILE

  fi
done

echo "Sending mail ..."
mail -s "HoneyPi report $DATE" $DESTINATION_EMAIL < $OUTPUT_FILE
echo "Script end"
