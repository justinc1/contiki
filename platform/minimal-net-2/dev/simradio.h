#ifndef NULLRADIO_H
#define NULLRADIO_H

#include "dev/radio.h"

/*
 * Simulate radio via UNIX net socket.
 */

extern const struct radio_driver simradio_driver;
void simradio_interrupt();

#endif /* NULLRADIO_H */
