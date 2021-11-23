# Relates to the ongoing XDP/eBPF project at FIU
This repo is comprised of basically two parts:

-	**part 1** deals with creating an assessment package that a DTN operator
 	can use to see what recommendations, if any, can be made based on the 
	current settings of the system.

- 	**part 2** is a superset of part 1 and has 4 phases:
	* Starting
	* Assessment (part 1 and a bit more)
	* Learning
	* Tuning

#### Each part is independent of the other

**Part 1**

There are no known dependencies at this point. There are two relevant 
directories here:

```assess-tuning``` and ```packaging```

**To Compile:**
-	go to assess-tuning directory and run ```make```
-	For a quick test:
	*	type ```sudo ./dtnmenu``` to run with a menu interaction
	*	you will get output on your screen with the menu interaction
	*	type ```sudo ./dtn_tune``` to run without menu interaction
	* 	/tmp/tuningLog will contain the output from the last run

**To make a zip package:**
-	**Note:** you must compile as explained above before trying to make a pkg.
-	go to ```packaging``` directory
-	type ```sh ./createpkg.sh``` to create a zip file called dtntune.zip
-	```dtntune.zip``` consist of files from the ```assess-tuning``` directory
-	create a temp directory, copy the zip file into it, and type unzip *.zip
-	after unziping, run the commands as mentioned above "for a quick test"

**Part 2**

* test_dtn.c refers to a test module used to create user_dtn.c
* user_dtn.c is the actual module that will eventually run as the Tuning Module
* dtn_tune.c refers to the new stuff which only features the assessment portion
