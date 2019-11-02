struct ifc;
void relay_loop(struct ifc *ifc, unsigned int nifc);
extern volatile int loop_stop; /* Stops relay_loop(). */

