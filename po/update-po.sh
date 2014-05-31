#!/bin/sh

PACKAGE=rpm-installer
SRCROOT=..
POTFILES=POTFILES.in

#ALL_LINGUAS= am az be ca cs da de el en_CA en_GB es et fi fr hr hu it ja ko lv mk ml ms nb ne nl pa pl pt pt_BR ru rw sk sl sr sr@Latn sv ta tr uk vi zh_CN zh_TW
ALL_LINGUAS="en_US en_GB ja_JP ko_KR zh_CN"

XGETTEXT=/usr/bin/xgettext
MSGMERGE=/usr/bin/msgmerge

echo -n "Make ${PACKAGE}.pot  "
if [ ! -e $POTFILES ] ; then
	echo "$POTFILES not found"
	exit 1
fi

$XGETTEXT --default-domain=${PACKAGE} --directory=${SRCROOT} \
		--add-comments --keyword=_ --keyword=N_ --files-from=$POTFILES
if [ $? -ne 0 ]; then
	echo "xgettext error"
	exit 1
fi

if [ ! -f ${PACKAGE}.po ]; then
	echo "No such file: ${PACKAGE}.po"
	exit 1
fi

rm -f ${PACKAGE}.pot && mv ${PACKAGE}.po ${PACKAGE}.pot
echo "done"

for LANG in $ALL_LINGUAS; do
	echo "$LANG : "

	if [ ! -e $LANG.po ] ; then
		sed 's/CHARSET/UTF-8/g' ${PACKAGE}.pot > ${LANG}.po
		echo "${LANG}.po created"
	else
		if $MSGMERGE ${LANG}.po ${PACKAGE}.pot -o ${LANG}.new.po ; then
			if cmp ${LANG}.po ${LANG}.new.po > /dev/null 2>&1; then
				rm -f ${LANG}.new.po
			else
				if mv -f ${LANG}.new.po ${LANG}.po; then
					echo ""
				else
					echo "msgmerge for $LANG.po failed: cannot move $LANG.new.po to $LANG.po" 1>&2
					rm -f ${LANG}.new.po
					exit 1
				fi
			fi
		else
			echo "msgmerge for $LANG failed!"
			rm -f ${LANG}.new.po
		fi
	fi
	echo ""
done
