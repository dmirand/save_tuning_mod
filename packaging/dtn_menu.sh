#!/bin/sh
#
# dtnmenu - scripts launched at runnig of dtn_tune
# to do routine admintstative tasks
#

# when viewing this script, set tabstops to 4

# The main script is at the bottom, after all support functions are defined

return='Return to previous menu'
select_choice='Enter option : '

clear_screen()
{
	tput clear
}

enter_to_continue()
{
	printf '\n\t%s' "Hit ENTER to continue: "
	read junk
}

list_config()
{
	clear_screen
	zogshowallcfg
	printf '\n\nEnter configuration to list [default - currently loaded]: '
	read name
	if [ -z "$name" ]
	then
		out=/usr/home/zogadmin/log/cfg_loaded
	else
		out=/usr/home/zogadmin/log/cfg_$name
	fi
	clear_screen
	zoglistcfg $name > $out
	if [ $? = 0 ]
	then
		more -d $out
		printf '\n#%s' "This listing has been saved in '$out'"
	fi
	enter_to_continue
	return 0
}

create_config()
{
	clear_screen
	printf '\n\tEnter name for the new configuration: '
	read name
	if [ -z "$name" ]
	then
		printf '\n\t%s' "You must enter a name!"
		enter_to_continue
		return 0
	fi
	zogreportcfg $name > /dev/null 2>&1
	if [ $? = 0 ]
	then
		# the config exists already
		printf '\n\tConfiguration "%s" already exists - overwrite it? (y/n): ' \
			$name
		read answer
		if [ "$answer" != 'y' -a "$answer" != 'Y' ]
		then
			enter_to_continue
			return 0
		fi
		option='-f'
	else
		option=""
	fi
	printf '\n\tEnter the input file name to be used to create "%s"\n\t: ' \
		$name
	read file_name
	if [ -z "$file_name" ]
	then
		printf '\n\t%s' "You must enter a file name!"
		enter_to_continue
		return 0
	fi
	clear_screen
	printf '\n\t%s\n\t  ... ' \
		"Calling zogcreatecfg -i $file_name -n $name $option"
	sleep 1
	zogcreatecfg -i "$file_name" -n $name $option
	enter_to_continue
	return 0
}

delete_config()
{
	clear_screen
	zogshowallcfg
	printf '\n\n\tEnter name of configuration to be deleted: '
	read name
	if [ -z "$name" ]
	then
		printf '\n\t%s' "You must enter a name!"
		enter_to_continue
		return 0
	fi
	printf '\n\tAre you sure you want to delete "%s"? (y/n): ' "$name"
	read answer
	if [ "$answer" = 'y' -o "$answer" = 'Y' ]
	then
		printf '\n\t'
		zogdeletecfg $name
	fi
	enter_to_continue
	return 0
}

rename_config()
{
	clear_screen
	zogshowallcfg
	printf '\n\n\tEnter name of configuration to be renamed: '
	read name
	if [ -z "$name" ]
	then
		printf '\n\t%s' "You must enter a name!"
		enter_to_continue
		return 0
	fi
	if [ ! -f /etc/zog/config/$name/$name ]
	then
		echo "Configuration $name does not exist!" 1>&2
		enter_to_continue
		return 0
	fi
	printf '\n\n\tEnter new configuration name: '
	read newname
	if [ -z "$newname" ]
	then
		printf '\n\t%s' "You must enter a new name!"
		enter_to_continue
		return 0
	else
		zogchkcfgname "$newname"
		if [ $? != 0 ]
		then
			printf '\n\t%s' "INVALID CONFIGURATION NAME!"
			enter_to_continue
			return 0
		fi
	fi

	printf '\n\tAre you sure you want to rename "%s" to "%s"? (y/n): ' \
				"$name" "$newname"
	read answer
	if [ "$answer" = 'y' -o "$answer" = 'Y' ]
	then
		printf '\n\t'
		zogrenamecfg $name $newname
	fi

	enter_to_continue
	return 0
}

set_active()
{
	clear_screen
	zogshowallcfg
	printf '\n\n\tEnter name of next active configuration: '
	read name
	if [ -z "$name" ]
	then
		printf '\n\t%s' "You must enter a name!"
		enter_to_continue
		return 0
	fi
	zogsetactivecfg "$name"
	enter_to_continue
	return 0
}

create_simple()
{
	clear_screen
	printf '\n\tEnter name for the new configuration: '
	read name
	if [ -z "$name" ]
	then
		printf '\n\t%s' "You must enter a name!"
		enter_to_continue
		return 0
	fi
	zogreportcfg $name > /dev/null 2>&1
	if [ $? = 0 ]
	then
		# the config exists already
		printf '\n\tConfiguration "%s" already exists - overwrite it? (y/n): ' \
			$name
		read answer
		if [ "$answer" != 'y' -a "$answer" != 'Y' ]
		then
			enter_to_continue
			return 0
		fi
		option='-f'
	else
		option=""
	fi

	tF=/usr/home/zogadmin/log/zog_build_$name

	printf '\tEnter a Description: '
	read desc

	printf 'NAME=%s\n' "$name" > $tF
	printf 'DESCRIPTION="%s"\n' "$desc" >> $tF

	printf '\tEnter the number of HBA ports you are configuring: '
	read nports
	if [ -z "$nports" ] || ! expr $nports + 1 >/dev/null 2>&1 || \
		[ $nports -le 0 ] || [ $nports -gt 2 ]
	then
		printf '\t"%s" invalid - must be either 1 thru 2' "$nports"
		enter_to_continue
		return 0
	fi

	port=0
	while [ $port -lt $nports ]
	do
		printf '\tEnter the number of devices for Port %d: ' "$port"
		read ndevs
		if [ -z "$ndevs" ] || ! expr $ndevs + 1 >/dev/null 2>&1 || \
			[ $ndevs -le 0 ] || [ $ndevs -gt 256 ]
		then
			printf '\t"%s" invalid - must be between 1 and 256' "$ndevs"
			enter_to_continue
			return 0
		fi

		printf '\tEnter the 0 to 4 byte SMFID of the MVS LPAR: '
		read answer
		if [ `printf "$answer" | wc -c` -gt 4 ]
		then
			printf '\t'%s' invalid - must be 4 characters or less' "$answer"
			enter_to_continue
			return 0
		fi
		smfid=`echo "$answer" | awk '{print toupper($0)}'`
		[ -n "$smfid" ] && smfid="$smfid:"

		printf '\tEnter the 4 hex digit starting channel device number: '
		read answer
		chandev=`echo $answer | awk '{print toupper($0)}'`
		A=`printf '%04X' 0x"$chandev" 2>/dev/null`
		if [ $A != $chandev ]
		then
			printf '\t'%s' invalid - must be 4 hex deigits' "$chandev"
			enter_to_continue
			return 0
		fi
		#start at LUN 1
		printf 'LUN=(%d,1-%X),DEV=%s%s;\n' \
			"$port" "$ndevs" "$smfid" "$chandev" >> $tF
		port=`expr $port + 1`
	done
	printf '\n\t%s\n\t  ... ' \
	"Calling zogcreatecfg -i $tF -n $name $option"
	sleep 1
	zogcreatecfg -i $tF -n $name $option
	enter_to_continue
	return 0
}

Run_Dtn_Tune()
{
	clear_screen
	./dtn_tune
#if [ $? = 0 ]
#    then
	more -d /tmp/tuningLog	
	printf '\n#%s' "This output has been saved in /tmp/tuningLog"
    #fi
    enter_to_continue
	return 0

	repeat_lun_mapping=1
	while  [ $repeat_lun_mapping = 1 ]
	do
		clear_screen
		printf '\n\n\t%s\n\n\t%s\n\t%s\n\t%s\n\t%s\n\t%s\n\t%s\n\t%s\n\t%s\n\n\t%s' \
			"z/OpenGate Configuration Utilities" \
			"1) Show All Configurations" \
			"2) Display Configuration" \
			"3) Import Configuration from Input File" \
			"4) Create Simple Configuration" \
			"5) Delete Configuration" \
			"6) Set Next Active Configuration" \
			"7) Rename Configuration" \
			"8) $return" \
			"$select_choice"

		read answer
		case "$answer" in
			1)
				clear_screen
				out=/usr/home/zogadmin/log/zog_configs
				zogshowallcfg | tee $out
				printf '\n#%s' \
					"This listing has been saved in '$out'"
				enter_to_continue
				;;
			2)
				list_config
				;;
			3)
				create_config
				;;
			4)
				create_simple
				;;
			5)
				delete_config
				;;
			6)
				set_active
				;;
			7)
				rename_config
				;;
			q|8)
				repeat_lun_mapping=0
				;;
			*)
				;;
		esac
	done
	return 0
}

force_panic()
{
	clear_screen
	printf '\n\t%s\n\t%s\n\t%s\n\t%s\n\t%s\n\t%s\n\t%s\n\t%s\n\t%s\n\t%s\n' \
		"Forcing a panic on z/OpenGate will cause the OS to crash and produce"\
		"a dump of the OS. This is useful only if you suspect a serious kernel"\
		"problem. It will cause all active transfers to be aborted," \
		"and may generate warning messages on the system logs of MVS, UNIX" \
		"and Windows systems that are connected. It is usually wise to stop" \
		"all applications on other systems that are connected to this" \
		"z/OpenGate before continuing. However, this may change the state of"\
		"the kernel drivers, and you may wish to cause this dump without"\
		"stopping these application in order to retain the state 'as is'."\
		"After the system reboots, the dump can be found in /var/log/dump."
	printf '\n\tDo you wish to continue? (y/n): '
	read answer
	if [ "$answer" = 'y' -o "$answer" = 'Y' ]
	then
		command="sync;sleep 1;echo c > /proc/sysrq-trigger"
		printf '\n\tIssuing "%s" ...' "$command"
		sleep 1
		[ `id -u` != 0 ] && printf '\n\tEnter root '
		su -c "$command"
		exit 0
	fi
	enter_to_continue
	return 0
}

shutdown_zog()
{
	clear_screen
	if [ $# -gt 0  -a $1 = '-r' ]
	then
		command="reboot"
		prompt="Rebooting"
	elif [ $# -gt 0  -a $1 = '-s' ]
	then
		command="init 0"
		prompt="Shutting down"
	else
		enter_to_continue
		return 0
	fi
	printf '\n\t%s\n\t%s\n\t%s\n\t%s\n\t%s\n' \
		"$prompt z/OpenGate will cause all active transfers to be aborted," \
		"and may generate warning messages on the system logs of MVS, UNIX" \
		"and Windows systems that are connected. It is usually wise to stop" \
		"all applications on other systems that are connected to this" \
		"z/OpenGate before continuing."
	printf '\n\tDo you wish to continue? (y/n): '
	read answer
	if [ "$answer" = 'y' -o "$answer" = 'Y' ]
	then
		printf '\n\tIssuing "%s" ...' "$command"
		sleep 1
		[ `id -u` != 0 ] && printf '\n\tEnter root '
		su -c "$command"
		exit 0
	fi
	enter_to_continue
	return 0
}

update_zog()
{
	clear_screen
	printf \
	'\n\tEnter the full pathname of the z/OpenGate update file.\n\t: '
	read file_name
	if [ -f "$file_name" ]
	then
		file "$file_name" | grep --quiet 'x86_64.rpm: RPM'
		if [ $? = 0 ]
		then
			rpm -qp "$file_name" | grep --quiet "zopengate-2.1"
			if [ $? = 0 ]
			then
				su -c "rpm -e zopengate; rpm -i $file_name"
				printf "\n\tYou must reboot z/OpenGate to enable new release.\n"
			else
				printf '\n\tRPM "%s" is not for zopengate 2\n' "$file_name"
			fi
		else
			file "$file_name" | grep --quiet -i gzip
			if [ $? = 0 ]
			then
				tD=/usr/home/zogadmin/tmp/update.$$
				mkdir -p $tD
				oD=`pwd`
				[ `id -u` != 0 ] && printf '\n\tEnter root '
				su -c \
	"cd $tD;tar -xzf $file_name;sh ./install_zog_update;cd $oD;rm -rf $tD"
			else
				printf '\n\tBad format for file "%s"\n' "$file_name"
			fi
		fi
	else
		printf '\n\tFile "%s" not found!\n' "$file_name"
	fi
	enter_to_continue
	return 0
}

schedule_firmware_flash()
{
	clear_screen
	printf "\n\t%s\n\t%s\n\t%s\n\n\t%s\n\t%s\n\t%s\n" \
		"This command schedules the installtion of new firmware on both"\
		"FICON ports. Once the firmware update is scheduled, it will occur on"\
		"the next reboot of the system."\
	  	"CAUTION - updating the firmware is destructive to any communications"\
		"on the FICON ports. For this resaon, it is HIGHLY recommended that"\
		"the MVS chpids be configured off rebooting to perform the update."
	printf "Do you wish to continue (y/n) ? "
	read answer
	if [ "$answer" != 'y' -a "$answer" != 'Y' ]
	then
		enter_to_continue
		return 0
	fi
	fware="/etc/emulex/fw/fw_default.grp"
	printf "Please specify the pathname of firmware file\n  %s" \
		"(default = $fware): "
	read answer
	[ -n "$answer" ] && fware=$answer
	if [ -f "$fware" ]
	then
		printf "Scheduling firmware update\n"
		[ `id -u` != 0 ] && printf '\tEnter root '
		su -c "cp -p $fware /etc/emulex/fw_new.grp"
		if [ $? = 0 ]
		then
			printf "The firmware will be updated on the next reboot\n\t%s :"\
			"Do you wish to reboot now (y/n)"
			read answer
			if [ "$answer" = 'y' -o "$answer" = 'Y' ]
			then
				shutdown_zog -r
			else
				printf "Firmware will be updated on next z/OpenGate reboot\n"
			fi
		else
			printf "Error scheduling firmware update.!\n"
		fi
	else
		printf "Firmware file $fware does not exist!\n"
	fi
	enter_to_continue
	return 0
}

prune_logs()
{
	clear_screen
	printf '\n\t%s\n\t%s\n\t%s\n\n\t%s' \
		"This command removes z/OpenGate log files that are now longer" \
		"needed. Please specify how many days worth of logs you wish to" \
		"retain." \
		"Enter number of days (30 is the default) : "
	read days
	[ -z "$days" ] && days=30
	if ! expr $days + 1 >/dev/null 2>&1 || [ $days -lt 30 ]
	then
		printf '\n\t"%s" is invalid - must be integer >= 30!' "$days"
		enter_to_continue
		return 0
	fi
	printf '\n\t%s\n\t"%s" days? (y/n): ' \
		"Are you really sure you wish to delete logs older than" "$days"
	read answer
	if [ "$answer" != 'y' -a "$answer" != 'Y' ]
	then
		enter_to_continue
		return 0
	fi
	[ `id -u` != 0 ] && printf '\n\tEnter root '
	su -c "zogremovelogs $days"
	enter_to_continue
	return 0
}

change_passwords()
{
	repeat_change_password=1
	while  [ $repeat_change_password = 1 ]
	do
		clear_screen
		printf '\n\n\t%s\n\n\t%s\n\t%s\n\t%s\n\n\t%s' \
			"z/OpenGate Password Administration" \
			"1) Change root password" \
			"2) Change zogadmin password" \
			"3) $return" \
			"$select_choice"

		read answer
		case "$answer" in
			1)
				clear_screen
				[ `id -u` != 0 ] && printf '\n\tEnter root '
				su -c "passwd root"
				enter_to_continue
				;;
			2)
				clear_screen
				[ `id -u` != 0 ] && printf '\n\tEnter root '
				su -c "passwd zogadmin"
				enter_to_continue
				;;
			q|3)
				repeat_change_password=0
				;;
			*)
				;;
		esac
	done
	return 0
}

backup_system()
{
	clear_screen
	archive="zog_sys_`uname -n``date +_%m_%d_%Y`.tar.gz"
	printf "\nA tar archive called $archive"
	printf "\nwill be created in a directory of your choosing. This archive"
	printf "\nwill contain all LUN configuration files, as well as system"
	printf "\nfiles containing the network configuration, and other settings.\n"
	printf "\nIt is wise to choose a directory on a removable media,"
	printf "\nsuch as a USB memory device, or to move the tar archive"
	printf "\nlater to removable media, so that the system can be"
	printf "\nrestored in the event of a catastrophic hard disk failure."
	printf "\n\nEnter directory name [default: /tmp]:  "
	read DestDir
	[ -z "$DestDir" ] && DestDir="/tmp"
	if [ ! -d $DestDir ]
	then
		printf "\n\n$DestDir is not a directory!\n"
		enter_to_continue
		return 0
	fi
	if [ -f $DestDir/$archive ]
	then
		printf "\n$DestDir/$archive already exists.\n\n%s" \
			"Do you wish to overwrite it? (y/n): "
		read answer
		if [ "$answer" != 'y' -a "$answer" != 'Y' ]
		then
			enter_to_continue
			return 0
		fi
	fi
	[ `id -u` != 0 ] && printf '\nEnter root '
	bu="etc/zog etc/hosts etc/resolv.conf etc/sysconfig etc/xinetd.d"
	bu="$bu etc/passwd etc/group etc/shadow"
	su -c "cd /;tar -czf $DestDir/$archive $bu"
	if [ $? = 0 ]
	then
		printf "\n$DestDir/$archive created.\n"
	else
		printf "\nError creating $DestDir/$archive !\n"
	fi
	enter_to_continue
	return 0
}


# main execution thread
	repeat_main=1
	while  [ $repeat_main = 1 ]
	do
		clear_screen
		printf '\n\n\t%s\n\n\t%s\n\t%s\n\t%s\n\t%s\n\t%s\n\t%s\n\n\t%s' \
			"DTN Tuning Utilities" \
			"1) Run DTN Tune" \
			"2) Escape to Linux Shell" \
			"3) Exit" \
			"$select_choice"

		read answer
		case "$answer" in
			1)
				Run_Dtn_Tune
				;;
			2)
				clear_screen
				$SHELL
				enter_to_continue
				;;
			q|3)
				clear_screen
				exit 0
				;;
			*)
				;;
		esac
	done
	echo
