/*
 Navicat Premium Data Transfer

 Source Server         : localhost
 Source Server Type    : MySQL
 Source Server Version : 50505
 Source Host           : localhost
 Source Database       : vpnxs_radius

 Target Server Type    : MySQL
 Target Server Version : 50505
 File Encoding         : utf-8

 Date: 12/03/2015 14:22:59 PM
*/

-- ----------------------------
--  Table structure for `dedicated_addresses`
-- ----------------------------
DROP TABLE IF EXISTS tpt_radius_dedicated_addresses CASCADE;
CREATE TABLE tpt_radius_dedicated_addresses (
  id                 SERIAL PRIMARY KEY,
  user_id            int NULL UNIQUE,
  address            varchar(50) NOT NULL UNIQUE,
  time_added         int  NOT NULL,
  time_reserved      int  DEFAULT NULL,
  time_updated       int  NOT NULL
);

-- ----------------------------
--  Table structure for `dns`
-- ----------------------------
DROP TABLE IF EXISTS tpt_radius_dns CASCADE;
CREATE TABLE tpt_radius_dns (
  id                 SERIAL PRIMARY KEY,
  name               varchar(10) NOT NULL UNIQUE,
  one                varchar(50) NOT NULL UNIQUE,
  two                varchar(50) NOT NULL
);

-- ----------------------------
--  Table structure for `product`
-- ----------------------------
DROP TABLE IF EXISTS tpt_radius_products CASCADE;
CREATE TABLE tpt_radius_products (
  id                 SERIAL PRIMARY KEY,
  product            varchar(50) NOT NULL UNIQUE,
  max_sessions       int NOT NULL,
  ratelimit_up       int NULL,
  ratelimit_down     int NULL,
  ratelimit_unit     char NULL
);

-- ----------------------------
--  Table structure for `user`
-- ----------------------------
DROP TABLE IF EXISTS tpt_radius_users CASCADE;
CREATE TABLE tpt_radius_users (
  id                  SERIAL PRIMARY KEY,
  username            varchar(100) NOT NULL UNIQUE,
  password            varchar(255) NOT NULL,
  description         text,
  block_remaining     bigint NULL,
  active_until        timestamp with time zone NULL,
  dedicated_address   varchar(50) NULL UNIQUE,
  product_id          int NOT NULL REFERENCES tpt_radius_products (id),
  dns_id              int NULL REFERENCES tpt_radius_dns (id),
  created_at          timestamp with time zone NOT NULL,
  updated_at          timestamp with time zone NOT NULL
);

COMMENT ON COLUMN tpt_radius_users.active_until IS 'Account becomes inactive on given date';
COMMENT ON COLUMN tpt_radius_users.dedicated_address IS 'Static IP';
COMMENT ON COLUMN tpt_radius_users.dns_id IS 'DNS Pri+Sec';



-- ----------------------------
--  Table structure for `accounting`
-- ----------------------------
DROP TABLE IF EXISTS tpt_radius_accounting CASCADE;
CREATE TABLE tpt_radius_accounting (
  user_id             int NOT NULL REFERENCES tpt_radius_users (id),
  hostname            varchar(50) NOT NULL,
  bytes_in            bigint NOT NULL,
  bytes_out           bigint NOT NULL,
  packets_in          bigint NOT NULL,
  packets_out         bigint NOT NULL,
  created_at          timestamp with time zone NOT NULL,
  PRIMARY KEY (user_id, created_at, hostname)
);

COMMENT ON COLUMN tpt_radius_accounting.hostname IS 'RadiusD-server for unique key';

-- ----------------------------
--  Table structure for `session`
-- ----------------------------
DROP TABLE IF EXISTS tpt_radius_sessions CASCADE;
CREATE TABLE tpt_radius_sessions (
  session_id         varchar(20) NOT NULL,
  user_id            int NOT NULL REFERENCES tpt_radius_users (id),
  nas_address        varchar(50) NOT NULL,
  nas_port           varchar(200),
  bytes_in           bigint NOT NULL,
  bytes_out          bigint NOT NULL,
  packets_in         bigint NOT NULL,
  packets_out        bigint NOT NULL,
  session_time       bigint NOT NULL,
  client_address     varchar(50) NOT NULL,
  assigned_address   varchar(50) NOT NULL,
  PRIMARY KEY (session_id,user_id,nas_address)
);

COMMENT ON COLUMN tpt_radius_sessions.nas_address IS 'VPN Server';
COMMENT ON COLUMN tpt_radius_sessions.session_time IS 'Session open in sec';

-- ----------------------------
--  Table structure for `session_log_records`
-- ----------------------------
DROP TABLE IF EXISTS tpt_radius_session_log_records CASCADE;
CREATE TABLE tpt_radius_session_log_records (
  id                 SERIAL PRIMARY KEY,
  session_id         varchar(20) NOT NULL,
  user_id            int NOT NULL REFERENCES tpt_radius_users (id),
  nas_address        varchar(50) NOT NULL,
  nas_port           varchar(200),
  bytes_in           bigint NOT NULL,
  bytes_out          bigint NOT NULL,
  packets_in         bigint NOT NULL,
  packets_out        bigint NOT NULL,
  client_address     varchar(50) NOT NULL,
  assigned_address   varchar(50) NOT NULL,
  created_at         timestamp with time zone NOT NULL
);

