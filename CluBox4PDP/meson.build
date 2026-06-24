project('xpkt_clubox', 'c',
    version: '0.1',
    default_options: ['c_std=gnu99', 'optimization=3', 'warning_level=2']
)

cc = meson.get_compiler('c')

add_project_arguments('-march=native', language: 'c')
add_project_arguments('-ffast-math', language: 'c')

if cc.has_argument('-ftree-vectorize')
    add_project_arguments('-ftree-vectorize', language: 'c')
endif

m_dep = cc.find_library('m', required: true)

dpdk_dep = dependency('libdpdk')

# 定义源文件列表
sources = files(
    'main.c',
    'clubox.c',
    'pseudo_flow.c',
    'dissectors.c',
    'box_classifier.c'
)

# pcap PMD：用于 --vdev eth_pcap0,rx_pcap=... 回放 pcap 文件
# PMD 通过构造函数注册驱动，必须用 --whole-archive 强制链接，否则 EAL 找不到 eth_pcap 设备
# 安装后位于 /usr/local/lib/x86_64-linux-gnu/dpdk/pmds-23.0/
dpdk_pmds_dir = '/usr/local/lib/x86_64-linux-gnu/dpdk/pmds-23.0'

pcap_pmd = cc.find_library('rte_net_pcap',
    dirs: [dpdk_pmds_dir],
    required: false)

ext_deps = [dpdk_dep, m_dep]
link_args = ['-lm']

# -Dpcap_ratelimit=true  → add 1ms delay per burst (pcap replay training mode)
# -Dpcap_ratelimit=false → no delay (live traffic / deployment mode, default)
if get_option('pcap_ratelimit')
    add_project_arguments('-DPCAP_REPLAY_RATELIMIT', language: 'c')
    message('pcap replay rate-limit enabled (training mode)')
endif

if pcap_pmd.found()
    message('pcap PMD found, linking with --whole-archive')
    link_args += [
        '-L' + dpdk_pmds_dir,
        '-Wl,--whole-archive', '-lrte_net_pcap', '-Wl,--no-whole-archive',
        '-Wl,-rpath,' + dpdk_pmds_dir,
    ]
else
    message('pcap PMD not found; install DPDK with net/pcap driver')
endif

executable('xpkt_clubox',
    sources,
    dependencies: ext_deps,
    link_args: link_args
)