CREATE TABLE `scam_reports` (
	`id` int AUTO_INCREMENT NOT NULL,
	`userId` int NOT NULL,
	`urlHost` varchar(255) NOT NULL,
	`category` varchar(64) NOT NULL,
	`description` varchar(500),
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `scam_reports_id` PRIMARY KEY(`id`)
);
