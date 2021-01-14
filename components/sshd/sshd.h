/*
 * sshd.h
 *
 *  Created on: 12 ene. 2021
 *      Author: egonzalez
 */

#ifndef _SSHD_H_
#define _SSHD_H_

void start_sshd(void);

struct interactive_session {
    void (*is_handle_char_from_remote)(struct interactive_session*, char);
    void (*is_handle_char_from_local)(struct interactive_session*, char*, int);
    void (*is_exit)(void);
    void (*is_reset_timeout)(void);
    void *is_data;
};

void minicli_handle_command(struct interactive_session*, const char*);
void minicli_begin_interactive_session(struct interactive_session*);

#endif /* _SSHD_H_ */

