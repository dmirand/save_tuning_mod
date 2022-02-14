#!/bin/sh
#
# dtnmenu - scripts launched at runnig of dtn_tune
# to do routine admintstative tasks
#

# when viewing this script, set tabstops to 4

# The main script is at the bottom, after all support functions are defined

clear_screen()
{
	tput clear
}

prune_logs()
{
	clear_screen
	rm -rf /tmp/tuningLogOld.*
	echo 0 > /tmp/tuningLog.count
	return 0
}

apply_recommended_kernel_settings()
{
	if [ -f  /tmp/applyKernelDefFile ]
	then
		printf '\n###%s\n\n' "Applying Kernel Tuning Recommendations Permanently..."
		sysctlmodified=1

		nlines=`sed -n '1p' /tmp/applyKernelDefFile`	
		count=2

		if [ ${sysctlmodified} -eq 1 ]
		then
			echo "#Start of tuningMod modifications" >> /etc/sysctl.conf	
		fi

		while [ ${count} -lt ${nlines} ]
		do
			linenum=`sed -n "${count}p" /tmp/applyKernelDefFile`
			echo $linenum > /tmp/tun_app_command
			sh /tmp/tun_app_command
		
			if [ ${sysctlmodified} -eq 1 ]
			then
			echo "$linenum >> /etc/sysctl.conf" > /tmp/tun_app_command
			sh /tmp/tun_app_command
			fi

			count=`expr $count + 1`
		done	
		
		if [ ${sysctlmodified} -eq 1 ]
		then
			echo "#End of tuningMod modifications" >> /etc/sysctl.conf	
		fi

		rm -f /tmp/tun_app_command
		rm -f /tmp/applyKernelDefFile
	fi
	return 0
}

apply_recommended_bios_settings()
{
	if [ -f  /tmp/applyBiosDefFile ]
	then
		nlines=`sed -n '1p' /tmp/applyBiosDefFile`	
		count=2

		echo "#Applying BIOS Tuning Recommendations..." 

		while [ ${count} -lt ${nlines} ]
		do
			linenum=`sed -n "${count}p" /tmp/applyBiosDefFile`
			echo $linenum > /tmp/tun_app_command
			sh /tmp/tun_app_command 1>/dev/null
			count=`expr $count + 1`
		done	
		
		rm -f /tmp/tun_app_command
		rm -f /tmp/applyBiosDefFile
	fi
	return 0
}

apply_recommended_nic_settings()
{
	if [ -f  /tmp/applyNicDefFile ]
	then
		nlines=`sed -n '1p' /tmp/applyNicDefFile`	
		count=2

		echo "#Applying NIC Tuning Recommendations..." 

		while [ ${count} -lt ${nlines} ]
		do
			linenum=`sed -n "${count}p" /tmp/applyNicDefFile`
			echo $linenum > /tmp/tun_app_command
			sh /tmp/tun_app_command
			count=`expr $count + 1`
		done	
		
		echo "#Finished Applying NIC Tuning Recommendations..." 

		rm -f /tmp/tun_app_command
		rm -f /tmp/applyNicDefFile
	fi
	return 0
}

apply_all_recommended_settings()
{
	clear_screen
	if [ -f  /tmp/applyKernelDefFile -o -f /tmp/applyBiosDefFile -o -f  /tmp/applyNicDefFile ]
	then
		echo "#Applying All Tuning Recommendations..." 

		apply_recommended_kernel_settings
		apply_recommended_bios_settings
		apply_recommended_nic_settings

		echo "#Finished Applying All Tuning Recommendations..."	
	fi
	return 0
}

run_dtntune()
{
logcount=
	clear_screen
	printf '\n###%s\n\n' "Running Tuning Assessment..."
	if [ -f /tmp/tuningLog ]
	then
		logcount=`cat /tmp/tuningLog.count`
		cp /tmp/tuningLog /tmp/tuningLogOld.$logcount
		logcount=`expr $logcount + 1`
		echo $logcount > /tmp/tuningLog.count
	else
		echo 0 > /tmp/tuningLog.count
	fi
}

# main execution thread
run_dtntune
apply_all_recommended_settings
