create table users
(
	id int auto_increment
		primary key,
	name varchar(16) not null,
	safe_name varchar(16) not null,
	token char(32) not null,
	priv int not null,
	constraint users_name_uindex
		unique (name),
	constraint users_safe_name_uindex
		unique (safe_name),
	constraint users_token_uindex
		unique (token)
);

create table uploads
(
	id int auto_increment
		primary key,
	name varchar(32) not null comment 'unsure how long extension length could become',
	user_id int not null,
	`when` datetime default CURRENT_TIMESTAMP not null,
	size int not null,
	constraint uploads_name_uindex
		unique (name)
);
