There are currently two test source files: test-tls.c and test-notls.c.
The first tests adding TLS data to a file that already has TLS sections.
The second tests adding TLS data to a file without TLS sections.

In order to check whether new TLS data has been inserted, first run
test_tls.py on the binary of your choice.  Then you can run <file>.new.
If the output doesn't look weird, it probably didn't corrupt anything.

However, if you want to see that the new data was added and is accessible, 
look for the output line from the python script that says (values may vary):

New data starting at offset 212 (0xd4)

Then, using gdb (example using test-tls):

gdb-peda$ b get_my_num
Breakpoint 1 at 0x8048620: file test-tls.c, line 33.
gdb-peda$ r
...
[Switching to Thread 0xf7de9b40 (LWP 5464)]
...
gdb-peda$ x/4s 0xf7de9b40-0xd4
0xf7de9a6c:	"data that will hopefully go into thread local storage"
0xf7de9aa2:	""
0xf7de9aa3:	""
0xf7de9aa4:	"unique value"
gdb-peda$

Note that 0xf7de9aa4 is the address of tdata_buf from the source.
Output from the program confirms that it was loaded to the correct offset.
Gdb shows that we can find the data we added at the exact offset predicted.
The program also gets the address in the gs register, which shows it is
identical to the thread address, and therefore we can simply use gs-offset
to access our new TLS data.

In test-notls break at get_current instead.
