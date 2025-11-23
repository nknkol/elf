#include "mini_libc.h"

/*
 * Payload Main Entry
 * This function is called after the assembly stub saves the context.
 */
void payload_main(void)
{
    const char *msg = "\n"
                      "   [Payload] ---------------------------------------\n"
                      "   [Payload] >>> HIJACK SUCCESS! Control flow captured.\n"
                      "   [Payload] >>> Register state saved & restored.\n"
                      "   [Payload] ---------------------------------------\n";
    
    /* * Use our mini-libc write. 
     * Since we compiled with -fPIC, the string address is calculated 
     * relative to PC, so this works safely in a raw binary.
     */
    sys_write(1, msg, 245); // Length doesn't need to be exact for demo, just large enough
}