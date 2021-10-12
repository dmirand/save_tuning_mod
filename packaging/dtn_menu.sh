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

prune_logs()
{
	clear_screen
	printf '\n\t%s\n\t%s\n' \
		"This will remove all the old tuningLog log files except the" \
		"current one."
	printf '\n\t%s (y/n): ' \
		"Do you wish to continue? "
	read answer
	if [ "$answer" != 'y' -a "$answer" != 'Y' ]
	then
		enter_to_continue
		return 0
	fi
	rm -rf /tmp/tuningLogOld.*
	echo 0 > /tmp/tuningLog.count
	enter_to_continue
	return 0
}

run_dtntune()
{
logcount=
	clear_screen
	printf '\n###%s\n\n' "Running Tuning Assessment..."
	if [ -f /tmp/tuningLog ]
	then
		logcount=`tail -1 /tmp/tuningLog.count`
		cp /tmp/tuningLog /tmp/tuningLogOld.$logcount
		logcount=`expr $logcount + 1`
		echo $logcount >> /tmp/tuningLog.count
	else
		echo 0 > /tmp/tuningLog.count
	fi
	./dtn_tune
	if [ $? = 0 ]
   	then
		more -d /tmp/tuningLog	
		printf '\n###%s' "This output has been saved in /tmp/tuningLog"
	fi
    enter_to_continue
	return 0
}

# main execution thread
	repeat_main=1
	while  [ $repeat_main = 1 ]
	do
		clear_screen
		printf '\n\n\t%s\n\n\t%s\n\t%s\n\t%s\n\t%s\n\t%s' \
			"DTN Tuning Utility" \
			"1) Run DTN Tune" \
			"2) Prune Old Logs" \
			"3) Escape to Linux Shell" \
			"4) Exit" \
			"$select_choice"

		read answer
		case "$answer" in
			1)
				run_dtntune
				;;
			2)
				prune_logs
				;;
			3)
				clear_screen
				$SHELL
				clear_screen
				enter_to_continue
				;;
			q|4)
				clear_screen
				exit 0
				;;
			*)
				;;
		esac
	done
	echo
