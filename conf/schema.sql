CREATE SEQUENCE sample_id_seq;

CREATE TABLE sample(
	id INTEGER NOT NULL DEFAULT nextval('sample_id_seq') PRIMARY KEY,
	filename VARCHAR(128),
	insert_at TIMESTAMP,
	pin_param VARCHAR(256),
	md5 VARCHAR (32) /*UNIQUE*/
);

CREATE TABLE ins(
	sample_id INTEGER REFERENCES sample(id),
	id BIGINT,
	thread_id BIGINT,
	adr BIGINT,
	asm VARCHAR(128),
	name VARCHAR(128),
	comment VARCHAR(128),
	CONSTRAINT ins_pkey PRIMARY KEY (sample_id, id, thread_id)
);

CREATE TABLE reg(
	sample_id INTEGER,
	ins_id BIGINT,
	thread_id BIGINT,
	eax BIGINT,
	ebx BIGINT,
	ecx BIGINT,
	edx BIGINT,
	edi BIGINT,
	esi BIGINT,
	ebp BIGINT,
	esp BIGINT,
	eip BIGINT,
	eflags BIGINT,
	CONSTRAINT reg_pkey PRIMARY KEY (sample_id, ins_id, thread_id),
	FOREIGN KEY (sample_id, ins_id, thread_id) REFERENCES ins (sample_id, id, thread_id)
);


CREATE TABLE dump(
	sample_id INTEGER,
	ins_id BIGINT,
	thread_id BIGINT,
	adr_start BIGINT,
	adr_stop BIGINT,
	cur BIGINT,
	data BYTEA,
	CONSTRAINT dump_pkey PRIMARY KEY (sample_id, ins_id, thread_id, adr_start)/*,
	FOREIGN KEY (sample_id, ins_id) REFERENCES ins (sample_id, id)*/
);

