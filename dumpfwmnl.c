
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <time.h>
#include <assert.h>
#include <unistd.h>  /* getopt() */
#include <netinet/in.h>
#include <pcap.h>
#include <limits.h>
#include <fcntl.h>
#include <libgen.h>
#include <search.h>
#include <libmnl/libmnl.h>
#include <sys/file.h>

#include "fwmnl.h"

static char *printip(uint32_t ip)
{
	static int rot = 0;
	static char res[8][32];
	uint8_t *p;

	rot++;
	if(rot == 8)
		rot = 0;

	p = (uint8_t *)&ip;

	sprintf(res[rot], "%u.%u.%u.%u", p[3], p[2], p[1], p[0]);

	return res[rot];
}

static int session_attr_cb(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	/* skip unsupported attribute in user-space */
	if (mnl_attr_type_valid(attr, SSN_ATTR_MAX) < 0)
		return MNL_CB_OK;

	tb[type] = attr;
	return MNL_CB_OK;
}

void parse_session(const struct nlmsghdr *nlh, void *data)
{
	struct nlattr *tb[SSN_ATTR_MAX+1] = {};
	
	mnl_attr_parse(nlh, 0, session_attr_cb, tb);
		
	printf("session>> ");

	if (tb[SSN_LOGTS])
		printf("LOGTS=%u ", mnl_attr_get_u32(tb[SSN_LOGTS]));
	if (tb[SSN_STARTTS])
		printf("STARTTS=%u ", mnl_attr_get_u32(tb[SSN_STARTTS]));
	if (tb[SSN_ENDTS])
		printf("ENDTS=%u ", mnl_attr_get_u32(tb[SSN_ENDTS]));
	
	if (tb[SSN_SRC])
		printf("SRC=%s ", printip(mnl_attr_get_u32(tb[SSN_SRC])));
	if (tb[SSN_DST])
		printf("SRC=%s ", printip(mnl_attr_get_u32(tb[SSN_DST])));
	if (tb[SSN_SP])
		printf("SP=%u ", mnl_attr_get_u16(tb[SSN_SP]));
	if (tb[SSN_DP])
		printf("DP=%u ", mnl_attr_get_u16(tb[SSN_DP]));
	if (tb[SSN_PROTO])
		printf("PROTO=%u ", mnl_attr_get_u8(tb[SSN_PROTO]));
    
	if (tb[SSN_TODSTPKT])
		printf("TODSTPKT=%llu ", mnl_attr_get_u64(tb[SSN_TODSTPKT]));
	if (tb[SSN_TODSTBYT])
		printf("TODSTBYT=%llu ", mnl_attr_get_u64(tb[SSN_TODSTBYT]));
	if (tb[SSN_TOSRCPKT])
		printf("TOSRCPKT=%llu ", mnl_attr_get_u64(tb[SSN_TOSRCPKT]));
	if (tb[SSN_TOSRCBYT])
		printf("TOSRCBYT=%llu ", mnl_attr_get_u64(tb[SSN_TOSRCBYT]));
	
	if (tb[SSN_SRCDROPPKT])
		printf("SRCDROPPKT=%llu ", mnl_attr_get_u64(tb[SSN_SRCDROPPKT]));
	if (tb[SSN_DSTDROPPKT])
		printf("DSTDROPPKT=%llu ", mnl_attr_get_u64(tb[SSN_DSTDROPPKT]));
	
	if (tb[SSN_ALERTS])
		printf("=%u ", mnl_attr_get_u32(tb[SSN_ALERTS]));
	
    	if (tb[SSN_CONFIRMED])
		printf("CONFIRMED=%u ", mnl_attr_get_u8(tb[SSN_CONFIRMED]));
	if (tb[SSN_DEATH])
		printf("DEATH=%u ", mnl_attr_get_u8(tb[SSN_DEATH]));
	if (tb[SSN_DROP])
		printf("DROP=%u ", mnl_attr_get_u8(tb[SSN_DROP]));

	if (tb[SSN_USER])
		printf("USER=%s ", mnl_attr_get_str(tb[SSN_USER]));
	if (tb[SSN_GROUP])
		printf("GROUP=%s ", mnl_attr_get_str(tb[SSN_GROUP]));
	
	if (tb[SSN_URI])
		printf("URI=%s ", mnl_attr_get_str(tb[SSN_URI]));
	if (tb[SSN_URLTYPE])
		printf("URLTYPE=%s ", mnl_attr_get_str(tb[SSN_URLTYPE]));
	
	if (tb[SSN_FILENAME])
		printf("FILENAME=%s ", mnl_attr_get_str(tb[SSN_FILENAME]));
	if (tb[SSN_FILETYPE])
		printf("FILETYPE=%s ", mnl_attr_get_str(tb[SSN_FILETYPE]));
	if (tb[SSN_FILESIZE])
		printf("FILESIZE=%s ", mnl_attr_get_str(tb[SSN_FILESIZE]));
	if (tb[SSN_FILEUPLOAD])
		printf("FILEUPLOAD=%s ", mnl_attr_get_str(tb[SSN_FILEUPLOAD]));
	if (tb[SSN_MIMEFILE])
		printf("MIMEFILE=%s ", mnl_attr_get_str(tb[SSN_MIMEFILE]));
	if (tb[SSN_MIMEFROM])
		printf("MIMEFROM=%s ", mnl_attr_get_str(tb[SSN_MIMEFROM]));
	if (tb[SSN_MIMERCPTTO])
		printf("MIMERCPTTO=%s ", mnl_attr_get_str(tb[SSN_MIMERCPTTO]));
	if (tb[SSN_MIMEHDRS])
		printf("MIMEHDRS=%s ", mnl_attr_get_str(tb[SSN_MIMEHDRS]));
	if (tb[SSN_VIRUSNAME])
		printf("VIRUSNAME=%s ", mnl_attr_get_str(tb[SSN_VIRUSNAME]));
	if (tb[SSN_VIRUSTYPE])
		printf("VIRUSTYPE=%s ", mnl_attr_get_str(tb[SSN_VIRUSTYPE]));
	
	if (tb[SSN_APP])
		printf("APP=%s ", mnl_attr_get_str(tb[SSN_APP]));
	if (tb[SSN_APP2])
		printf("APP2=%s ", mnl_attr_get_str(tb[SSN_APP2]));
	if (tb[SSN_APP3])
		printf("APP3=%s ", mnl_attr_get_str(tb[SSN_APP3]));
	if (tb[SSN_QQID])
		printf("QQID=%s ", mnl_attr_get_str(tb[SSN_QQID]));
	
	if (tb[SSN_USERIP])
		printf("USERIP=%s ", mnl_attr_get_str(tb[SSN_USERIP]));
	if (tb[SSN_DSTUSERIP])
		printf("DSTUSERIP=%s ", mnl_attr_get_str(tb[SSN_DSTUSERIP]));
	if (tb[SSN_HTPREQCOOKIE])
		printf("HTPREQCOOKIE=%s ", mnl_attr_get_str(tb[SSN_HTPREQCOOKIE]));
	if (tb[SSN_HTPRESCOOKIE])
		printf("HTPRESCOOKIE=%s ", mnl_attr_get_str(tb[SSN_HTPRESCOOKIE]));
	if (tb[SSN_HTPREQHEADER])
		printf("HTPREQHEADER=%s ", mnl_attr_get_str(tb[SSN_HTPREQHEADER]));
	if (tb[SSN_HTPRESHEADER])
		printf("HTPRESHEADER=%s ", mnl_attr_get_str(tb[SSN_HTPRESHEADER]));
	if (tb[SSN_ZONE])
		printf("ZONE=%s ", mnl_attr_get_str(tb[SSN_ZONE]));
	if (tb[SSN_INDEV])
		printf("INDEV=%s ", mnl_attr_get_str(tb[SSN_INDEV]));
	if (tb[SSN_INDEV2])
		printf("INDEV2=%s ", mnl_attr_get_str(tb[SSN_INDEV2]));
	if (tb[SSN_OUTDEV])
		printf("OUTDEV=%s ", mnl_attr_get_str(tb[SSN_OUTDEV]));
	if (tb[SSN_OUTDEV2])
		printf("OUTDEV2=%s ", mnl_attr_get_str(tb[SSN_OUTDEV2]));
	if (tb[SSN_DSTZONE])
		printf("DSTZONE=%s ", mnl_attr_get_str(tb[SSN_DSTZONE]));
	if (tb[SSN_DSTUSER])
		printf("DSTUSER=%s ", mnl_attr_get_str(tb[SSN_DSTUSER]));
	if (tb[SSN_DSTGROUP])
		printf("DSTGROUP=%s ", mnl_attr_get_str(tb[SSN_DSTGROUP]));
	if (tb[SSN_ACZONE])
		printf("ACZONE=%s ", mnl_attr_get_str(tb[SSN_ACZONE]));
	if (tb[SSN_DSTACZONE])
		printf("DSTACZONE=%s ", mnl_attr_get_str(tb[SSN_DSTACZONE]));

	printf("\n");
}

void parse_alert(const struct nlmsghdr *nlh, void *data)
{
	struct nlattr *tb[ALERT_ATTR_MAX+1] = {};
	
	mnl_attr_parse(nlh, 0, session_attr_cb, tb);
		
	printf("alert>> ");

	if (tb[ALERT_LOGTS])
		printf("LOGTS=%u ", mnl_attr_get_u32(tb[ALERT_LOGTS]));
	
	if (tb[ALERT_SRC])
		printf("SRC=%s ", printip(mnl_attr_get_u32(tb[ALERT_SRC])));
	if (tb[ALERT_DST])
		printf("SRC=%s ", printip(mnl_attr_get_u32(tb[ALERT_DST])));
	if (tb[ALERT_SP])
		printf("SP=%u ", mnl_attr_get_u16(tb[ALERT_SP]));
	if (tb[ALERT_DP])
		printf("DP=%u ", mnl_attr_get_u16(tb[ALERT_DP]));
	if (tb[ALERT_PROTO])
		printf("PROTO=%u ", mnl_attr_get_u8(tb[ALERT_PROTO]));
	
	if (tb[ALERT_SNORTID])
		printf("PROTO=%u ", mnl_attr_get_u32(tb[ALERT_SNORTID]));
	if (tb[ALERT_GID])
		printf("PROTO=%u ", mnl_attr_get_u32(tb[ALERT_GID]));
	if (tb[ALERT_SID])
		printf("PROTO=%u ", mnl_attr_get_u32(tb[ALERT_SID]));
	
	if (tb[ALERT_SNORTTYPE])
		printf("PROTO=%s ", mnl_attr_get_str(tb[ALERT_SNORTTYPE]));
	if (tb[ALERT_LOGTYPE])
		printf("PROTO=%s ", mnl_attr_get_str(tb[ALERT_LOGTYPE]));
	if (tb[ALERT_LOGTYPE2])
		printf("PROTO=%s ", mnl_attr_get_str(tb[ALERT_LOGTYPE2]));
	if (tb[ALERT_LOGMSG])
		printf("PROTO=%s ", mnl_attr_get_str(tb[ALERT_LOGMSG]));

	printf("\n");
}

void parse_attack(const struct nlmsghdr *nlh, void *data)
{
	struct nlattr *tb[ATTACK_ATTR_MAX+1] = {};
	
	mnl_attr_parse(nlh, 0, session_attr_cb, tb);
		
	printf("attack>> ");

	if (tb[ATTACK_LOGTS])
		printf("LOGTS=%u ", mnl_attr_get_u32(tb[ATTACK_LOGTS]));
	
	if (tb[ATTACK_SRC])
		printf("SRC=%s ", printip(mnl_attr_get_u32(tb[ATTACK_SRC])));
	if (tb[ATTACK_DST])
		printf("SRC=%s ", printip(mnl_attr_get_u32(tb[ATTACK_DST])));
	if (tb[ATTACK_SP])
		printf("SP=%u ", mnl_attr_get_u16(tb[ATTACK_SP]));
	if (tb[ATTACK_DP])
		printf("DP=%u ", mnl_attr_get_u16(tb[ATTACK_DP]));
	if (tb[ATTACK_PROTO])
		printf("PROTO=%u ", mnl_attr_get_u8(tb[ATTACK_PROTO]));
	
	if (tb[ATTACK_TYPE])
		printf("TYPE=%s ", mnl_attr_get_str(tb[ATTACK_TYPE]));
	if (tb[ATTACK_ACTION])
		printf("ACTION=%s ", mnl_attr_get_str(tb[ATTACK_ACTION]));

	printf("\n");
}

static int data_cb(const struct nlmsghdr *nlh, void *data)
{
//	fprintf(stdout, "nlmsg_len=%u nlmsg_type=%u nlmsg_pid=%x\n", nlh->nlmsg_len, nlh->nlmsg_type, nlh->nlmsg_pid);
	
	if (nlh->nlmsg_type == FW_MNL_SESSION) {
		parse_session(nlh, data);
	}
	else
	if (nlh->nlmsg_type == FW_MNL_ALERT) {
		parse_alert(nlh, data);
	}
	else
	if (nlh->nlmsg_type == FW_MNL_ATTACK) {
		parse_attack(nlh, data);
	}
	
	return MNL_CB_OK;
}

/**
 * Help function to print usage information.
 */
void print_usage(const char* pro_name)
{
	fprintf(stderr, "Usage: %s [-f filepath #default '%s'] [-r]\n", pro_name, FW_LOGFILE);
	exit(0);
}

/**
 * Main portal of http-sniffer
 */
int main(int argc, char *argv[])
{
	int opt, fd, ret, r = 0, fdlock;
	off_t fsize;
	char *path = FW_LOGFILE, rlpath[512], *nlmsg_buf;

	// Parse arguments
	while ((opt = getopt(argc, argv, "rf:h")) != -1) {
		switch (opt) {
		case 'h':
			print_usage(argv[0]); return (1);
		case 'f':
			path = optarg; break;
		case 'r':
			r = 1; break;
		default:
			print_usage(argv[0]); return (1);
		}
	}

	if (r == 1) {
		sprintf(rlpath, "%s.tmp", path);
		unlink(rlpath);
		
    		fdlock = open(FW_LOGFILE_LOCK, O_RDWR|O_CREAT, S_IRUSR|S_IWUSR);
		if (fdlock <= 0) {
			printf("failed lock file '%s'.\n", FW_LOGFILE_LOCK);
			return 0;
		}
		flock(fdlock, LOCK_EX);
		
		if (rename(path, rlpath) != 0) { // ### :-)
			fprintf(stderr, "failed rename '%s' to '%s'\n", path, rlpath);
    			flock(fdlock, LOCK_UN);
		    	close(fdlock);
			exit(2);
		}
    		flock(fdlock, LOCK_UN);
	    	close(fdlock);
	} else {
		sprintf(rlpath, "%s", path);
	}

	fd = open(rlpath, O_RDONLY);
	if (fd <= 0) {
		fprintf(stderr, "failed open '%s'\n", rlpath);
		exit(1);
	}
	
	fsize = lseek(fd, 0, SEEK_END);
	if (fsize > 0) {
		lseek(fd, 0, SEEK_SET);
		nlmsg_buf = malloc(fsize+1);
		if (nlmsg_buf == NULL) {
			fprintf(stderr, "failed malloc nlmsg_buf.\n");
			exit(2);
		}
		if (read(fd, nlmsg_buf, fsize) != fsize) {
			fprintf(stderr, "failed read nlmsg_buf.\n");
			exit(3);
		}

		ret = mnl_cb_run(nlmsg_buf, fsize, 0, 0, data_cb, NULL);
		if (ret < 0) {
			fprintf(stderr, "err in mnl_cb_run.\n");
			exit(4);
		}

		free(nlmsg_buf);
	}

	close(fd);

	return 0;
}
