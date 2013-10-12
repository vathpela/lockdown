/*
 * Copyright 2013 Red Hat, Inc <pjones@redhat.com>
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 
 * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * 
 * Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the
 * distribution.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */
	.globl kek_len
	.data
	.align 16
	.type	kek_len, @object
	.size	kek_len, 4
	.section .data, "a", @progbits
kek_len:
	.long	kek_end - kek
	.globl kek
	.data
	.align	1
	.type	kek, @object
	.size	kek, kek_end-kek
	.section .data, "a", @progbits
kek:
.incbin KEK_FILE
kek_end:

	.globl db_len
	.data
	.align 16
	.type	db_len, @object
	.size	db_len, 4
	.section .data, "a", @progbits
db_len:
	.long	db_end - db
	.globl db
	.data
	.align	1
	.type	db, @object
	.size	db, db_end-db
	.section .data, "a", @progbits
db:
.incbin DB_FILE
db_end:

	.globl pk_len
	.data
	.align 16
	.type	pk_len, @object
	.size	pk_len, 4
	.section .data, "a", @progbits
pk_len:
	.long	pk_end - pk
	.globl pk
	.data
	.align	1
	.type	pk, @object
	.size	pk, pk_end-pk
	.section .data, "a", @progbits
pk:
.incbin PK_FILE
pk_end:

