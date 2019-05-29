#!/bin/sh

NAME="gotee"
CURRENT=`pwd`
FILE="_run.sh"

#Creating the command file.
if [ -f "$FILE" ]; then
	rm -f $FILE
fi

echo "
#!/bin/bash
CURRENT=\"$CURRENT\"
GOROOT=$CURRENT $CURRENT/bin/go \$@
" > $FILE

chmod +x $FILE

# Installing command.
echo "Installing cmd as $NAME"
echo "........................."
rm /usr/local/bin/$NAME
ln -s $CURRENT/$FILE /usr/local/bin/$NAME
echo "Done."
which $NAME
echo "........................."


