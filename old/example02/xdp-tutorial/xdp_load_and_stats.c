/* SPDX-License-Identifier: GPL-2.0 */
static const char *__doc__ = "XDP loader and stats program\n"
	" - Allows selecting BPF --progname name to XDP-attach to --dev\n";

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>

#include <locale.h>
#include <unistd.h>
#include <time.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <xdp/libxdp.h>

#include <net/if.h>
#include <linux/if_link.h> /* depend on kernel-headers installed */

#include "./common/common_params.h"
#include "./common/common_user_bpf_xdp.h"
#include "common_kern_user.h"

static const char *default_filename = "xdp_prog_kern.o";
static const char *default_progname = "xdp_stats1_func";

static const struct option_wrapper long_options[] = {
	{{"help",        no_argument,		NULL, 'h' },
	 "Show help", false},

	{{"dev",         required_argument,	NULL, 'd' },
	 "Operate on device <ifname>", "<ifname>", true},

	{{"skb-mode",    no_argument,		NULL, 'S' },
	 "Install XDP program in SKB (AKA generic) mode"},

	{{"native-mode", no_argument,		NULL, 'N' },
	 "Install XDP program in native mode"},

	{{"auto-mode",   no_argument,		NULL, 'A' },
	 "Auto-detect SKB or native mode"},

	{{"unload",      required_argument,	NULL, 'U' },
	 "Unload XDP program <id> instead of loading", "<id>"},

	{{"unload-all",  no_argument,           NULL,  4  },
	 "Unload all XDP programs on device"},

	{{"quiet",       no_argument,		NULL, 'q' },
	 "Quiet mode (no output)"},

	{{"filename",    required_argument,	NULL,  1  },
	 "Load program from <file>", "<file>"},

	{{"progname",    required_argument,	NULL,  2  },
	 "Load program from function <name> in the ELF file", "<name>"},

	{{0, 0, NULL,  0 }}
};

int find_map_fd(struct bpf_object *bpf_obj, const char *mapname)
{
	struct bpf_map *map;
	int map_fd = -1;

	/* Lesson#3: bpf_object to bpf_map */
	map = bpf_object__find_map_by_name(bpf_obj, mapname);
	if (!map) {
		fprintf(stderr, "ERR: cannot find map by name: %s\n", mapname);
		goto out;
	}

	map_fd = bpf_map__fd(map);
 out:
	return map_fd;
}

#define NANOSEC_PER_SEC 1000000000 /* 10^9 */
static __u64 gettime(void)
{
	struct timespec t;
	int res;

	res = clock_gettime(CLOCK_MONOTONIC, &t);
	if (res < 0) {
		fprintf(stderr, "Error with gettimeofday! (%i)\n", res);
		exit(EXIT_FAIL);
	}
	return (__u64) t.tv_sec * NANOSEC_PER_SEC + t.tv_nsec;
}

struct record {
	__u64 timestamp;
	struct datarec total; /* defined in common_kern_user.h */
};

struct stats_record {
	struct record stats[XDP_ACTION_MAX]; /* Assignment#2: Hint */
};

static double calc_period(struct record *r, struct record *p)
{
	double period_ = 0;
	__u64 period = 0;

	period = r->timestamp - p->timestamp;
	if (period > 0)
		period_ = ((double) period / NANOSEC_PER_SEC);

	return period_;
}

static void stats_print(struct stats_record *stats_rec,
			struct stats_record *stats_prev)
{
	struct record *rec, *prev;
	double period;
	__u64 packets, bytes;
	double pps, bps;

	// 헤더 출력
	printf("%-12s %-18s %-18s %s\n", 
           "Action", "Packets(pps)", "Bytes(Mbits/s)", "Period");

	/* [Assignment 2] 모든 XDP 액션을 순회하며 출력 */
	for (int i = 0; i < XDP_ACTION_MAX; i++) {
		char *fmt = "%-12s %'11lld pkts (%'10.0f pps) %'11lld bytes (%'6.0f Mbits/s) %f\n";
		const char *action_str = action2str(i); // common 라이브러리 함수

		rec  = &stats_rec->stats[i];
		prev = &stats_prev->stats[i];

		period = calc_period(rec, prev);
		if (period == 0) continue;

		packets = rec->total.rx_packets - prev->total.rx_packets;
		bytes   = rec->total.rx_bytes   - prev->total.rx_bytes; // [Assignment 1]

		// 변화가 없는 액션은 출력 생략 (화면 깔끔하게)
		if (packets == 0 && bytes == 0) continue;

		pps = packets / period;
		bps = (bytes * 8) / period / 1000000.0; // Mbits/s 계산

		printf(fmt, action_str, rec->total.rx_packets, pps, 
               rec->total.rx_bytes, bps, period);
	}
    printf("\n");
}

/* BPF_MAP_TYPE_ARRAY */
void map_get_value_array(int fd, __u32 key, struct datarec *value)
{
	if ((bpf_map_lookup_elem(fd, &key, value)) != 0) {
		fprintf(stderr,
			"ERR: bpf_map_lookup_elem failed key:0x%X\n", key);
	}
}

/* BPF_MAP_TYPE_PERCPU_ARRAY */
void map_get_value_percpu_array(int fd, __u32 key, struct datarec *value)
{
	/* For percpu maps, userspace gets a value per possible CPU */
	// unsigned int nr_cpus = libbpf_num_possible_cpus();
	// struct datarec values[nr_cpus];
	
	unsigned int nr_cpus = libbpf_num_possible_cpus();
	struct datarec values[nr_cpus];
	__u64 sum_bytes = 0;
	__u64 sum_pkts = 0;
	int i;

	if ((bpf_map_lookup_elem(fd, &key, values)) != 0) {
		fprintf(stderr,
			"ERR: bpf_map_lookup_elem failed key:0x%X\n", key);
		return;
	}

	/* Sum values from each CPU */
	for (i = 0; i < nr_cpus; i++) {
		sum_pkts  += values[i].rx_packets;
		sum_bytes += values[i].rx_bytes;
	}
	value->rx_packets = sum_pkts;
	value->rx_bytes   = sum_bytes;

	//fprintf(stderr, "ERR: %s() not impl. see assignment#3", __func__);
}



static bool map_collect(int fd, __u32 key, struct record *rec)
{
	struct datarec value;

	/* Get time as close as possible to reading map contents */
	rec->timestamp = gettime();

	if ((bpf_map_lookup_elem(fd, &key, &value)) != 0) {
		// 맵에 키가 없을 수도 있음 (아직 해당 액션이 발생 안 했을 때 등)
		// 에러라기보단 0으로 처리
		value.rx_packets = 0;
		value.rx_bytes = 0;
	}

	rec->total.rx_packets = value.rx_packets;
	rec->total.rx_bytes   = value.rx_bytes; // [Assignment 1] 값 복사
	return true;
}

static void stats_collect(int map_fd, struct stats_record *stats_rec)
{
	for (int i = 0; i < XDP_ACTION_MAX; i++) {
		map_collect(map_fd, i, &stats_rec->stats[i]);
	}
}

static void stats_poll(int map_fd, __u32 map_type, int interval)
{
	struct stats_record prev, record = { 0 };

	/* Trick to pretty printf with thousands separators use %' */
	setlocale(LC_NUMERIC, "en_US");

	/* 초기값 읽기 */
	stats_collect(map_fd, &record);
	usleep(1000000/4);

	while (1) {
		prev = record; 
		stats_collect(map_fd, &record);
		stats_print(&record, &prev);
		sleep(interval);
	}
}

/* Lesson#4: It is userspace responsibility to known what map it is reading and
 * know the value size. Here get bpf_map_info and check if it match our expected
 * values.
 */
static int __check_map_fd_info(int map_fd, struct bpf_map_info *info,
			       struct bpf_map_info *exp)
{
	__u32 info_len = sizeof(*info);
	int err;

	if (map_fd < 0)
		return EXIT_FAIL;

	/* BPF-info via bpf-syscall */
	err = bpf_obj_get_info_by_fd(map_fd, info, &info_len);
	if (err) {
		fprintf(stderr, "ERR: %s() can't get info - %s\n",
			__func__,  strerror(errno));
		return EXIT_FAIL_BPF;
	}

	if (exp->key_size && exp->key_size != info->key_size) {
		fprintf(stderr, "ERR: %s() "
			"Map key size(%d) mismatch expected size(%d)\n",
			__func__, info->key_size, exp->key_size);
		return EXIT_FAIL;
	}
	if (exp->value_size && exp->value_size != info->value_size) {
		fprintf(stderr, "ERR: %s() "
			"Map value size(%d) mismatch expected size(%d)\n",
			__func__, info->value_size, exp->value_size);
		return EXIT_FAIL;
	}
	if (exp->max_entries && exp->max_entries != info->max_entries) {
		fprintf(stderr, "ERR: %s() "
			"Map max_entries(%d) mismatch expected size(%d)\n",
			__func__, info->max_entries, exp->max_entries);
		return EXIT_FAIL;
	}
	if (exp->type && exp->type  != info->type) {
		fprintf(stderr, "ERR: %s() "
			"Map type(%d) mismatch expected type(%d)\n",
			__func__, info->type, exp->type);
		return EXIT_FAIL;
	}

	return 0;
}

int main(int argc, char **argv)
{
	struct bpf_map_info info = { 0 };
	struct xdp_program *program;
	int stats_map_fd;
	int interval = 2;
	char errmsg[1024];
	int err;

	struct config cfg = {
		.ifindex   = -1,
		.do_unload = false,
	};
	/* Set default BPF-ELF object file and BPF program name */
	strncpy(cfg.filename, default_filename, sizeof(cfg.filename));
	strncpy(cfg.progname,  default_progname,  sizeof(cfg.progname));
	/* Cmdline options can change progname */
	parse_cmdline_args(argc, argv, long_options, &cfg, __doc__);

	/* Required option */
	if (cfg.ifindex == -1) {
		fprintf(stderr, "ERR: required option --dev missing\n");
		usage(argv[0], __doc__, long_options, (argc == 1));
		return EXIT_FAIL_OPTION;
	}

	/* Unload a program by prog_id, or
	 * unload all programs on net device
	 */
	if (cfg.do_unload || cfg.unload_all) {
		err = do_unload(&cfg);
		if (err) {
			libxdp_strerror(err, errmsg, sizeof(errmsg));
			fprintf(stderr, "Couldn't unload XDP program %d: %s\n",
				cfg.prog_id, errmsg);
			return err;
		}

		printf("Success: Unloading XDP prog name: %s\n", cfg.progname);
		return EXIT_OK;
	}

	/* 1. 이 함수 안에서 .o 파일을 읽고, 커널에 로드하고, 
	 * 내부적으로 bpf_object라는 장부를 생성합니다. 
	 * common 라이브러리에 정의된 헬퍼 함수   
	 * 파일 열기 → 커널에 올리기 → 네트워크 카드에 붙이기 */
	program = load_bpf_and_xdp_attach(&cfg);
	if (!program)
		return EXIT_FAIL_BPF;

	if (verbose) {
		printf("Success: Loaded BPF-object(%s) and used section(%s)\n",
		       cfg.filename, cfg.progname);
		printf(" - XDP prog id:%d attached on device:%s(ifindex:%d)\n",
		       xdp_program__id(program), cfg.ifname, cfg.ifindex);
	}
	
	
	// [중요] 맵 검증 설정 (Assignment에 맞춰 변경됨)
	struct bpf_map_info map_expect = { 0 };
	map_expect.key_size    = sizeof(__u32);
	map_expect.value_size  = sizeof(struct datarec);
	map_expect.max_entries = XDP_ACTION_MAX; // [Assignment 2] 크기 확인
	
	

	/* 2. program 구조체에서 장부(bpf_object)를 꺼냅니다. */
	/* 3. 장부에서 이름표를 보고 FD를 찾습니다.
 	* "이 장부에서 이름이 'xdp_stats_map'인 거 찾아줘" */
	stats_map_fd = find_map_fd(xdp_program__bpf_obj(program), "xdp_stats_map");
	if (stats_map_fd < 0) {
		/* xdp_link_detach(cfg.ifindex, cfg.xdp_flags, 0); */
		return EXIT_FAIL_BPF;
	}

	/* Lesson#4: check map info, e.g. datarec is expected size */
	map_expect.key_size    = sizeof(__u32);
	map_expect.value_size  = sizeof(struct datarec);
	map_expect.max_entries = XDP_ACTION_MAX;
	err = __check_map_fd_info(stats_map_fd, &info, &map_expect);
	if (err) {
		fprintf(stderr, "ERR: map via FD not compatible\n");
		return err;
	}
	if (verbose) {
		printf("\nCollecting stats from BPF map\n");
		printf(" - BPF map (bpf_map_type:%d) id:%d name:%s"
		       " key_size:%d value_size:%d max_entries:%d\n",
		       info.type, info.id, info.name,
		       info.key_size, info.value_size, info.max_entries
		       );
	}

	stats_poll(stats_map_fd, info.type, interval);
	return EXIT_OK;
}
