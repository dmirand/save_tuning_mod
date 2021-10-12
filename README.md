# Relates to the ongoing XDP/eBPF project at FIU
This repo has changes to run a userspace process with a kernel module.

* test_dtn.c refers to a test module used to create user_dtn.c
* user_dtn.c is the actual module that will eventually run as the Tuning Module
* dtn_tune.c refers to the new stuff which only features the assessment portion
