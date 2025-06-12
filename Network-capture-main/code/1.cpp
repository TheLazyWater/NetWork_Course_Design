#include "1.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QDateTime>
#include <QFileDialog>
#include <QFile>
#include <QTextStream>
#include <QMessageBox>
#include <QDebug>
#include <QComboBox>
#include <QLineEdit>  // 确保QLineEdit的头文件已包含
#include <algorithm>  // 用于std::max

// 以太网头部结构
typedef struct ether_header {
    u_char ether_dhost[6];
    u_char ether_shost[6];
    u_short ether_type;
} ether_header;

// IP头部结构
typedef struct ip_header {
    u_char  ver_ihl;
    u_char  tos;
    u_short tlen;
    u_short identification;
    u_short flags_fo;
    u_char  ttl;
    u_char  proto;
    u_short crc;
    u_int   saddr;
    u_int   daddr;
    u_int   op_pad;
} ip_header;

// TCP头部结构
typedef struct tcp_header {
    u_short th_sport;
    u_short th_dport;
    u_int   th_seq;
    u_int   th_ack;
    u_char  th_offx2;
    u_char  th_flags;
    u_short th_win;
    u_short th_sum;
    u_short th_urp;
} tcp_header;

// UDP头部结构
typedef struct udp_header {
    u_short uh_sport;
    u_short uh_dport;
    u_short uh_ulen;
    u_short uh_sum;
} udp_header;

#include <QtCharts/QChartView>
#include <QtCharts/QLineSeries>
#include <QtCharts/QBarSeries>
#include <QtCharts/QDateTimeAxis>
#include <QtCharts/QValueAxis>
#include <QtCharts/QBarCategoryAxis>
#include <QtCharts/QBarSet>

QT_CHARTS_USE_NAMESPACE

void packet_handler(u_char *userData, const struct pcap_pkthdr *header, const u_char *data) {
    TrafficAnalyzer *analyzer = reinterpret_cast<TrafficAnalyzer*>(userData);
    analyzer->processPacket(header, data);
}

CaptureThread::CaptureThread(pcap_t *handle, QObject *parent)
    : QThread(parent), m_handle(handle), m_running(true)
{
}

CaptureThread::~CaptureThread()
{
    stopCapture();
    wait();
}

void CaptureThread::stopCapture()
{
    m_running = false;
    if (m_handle) {
        pcap_breakloop(m_handle);
    }
}

void CaptureThread::run()
{
    struct pcap_pkthdr header;
    const u_char *data;

    while (m_running) {
        data = pcap_next(m_handle, &header);
        if (data && m_running) {
            emit packetCaptured(&header, data);
        }
    }
}

TrafficAnalyzer::TrafficAnalyzer(QWidget *parent) : QWidget(parent),
                                                     m_handle(nullptr),
                                                     isAnalyzing(false),
                                                     timeWindowSeconds(60),
                                                     m_captureThread(nullptr)
{
    setupUI();
    setupCharts();

    updateTimer = new QTimer(this);
    connect(updateTimer, &QTimer::timeout, this, &TrafficAnalyzer::updateCharts);

    resetAnalysis();
}

TrafficAnalyzer::~TrafficAnalyzer()
{
    stopAnalysis();
}

void TrafficAnalyzer::setupUI()
{
    QVBoxLayout *mainLayout = new QVBoxLayout(this);

    QHBoxLayout *controlLayout1 = new QHBoxLayout();
    QComboBox *deviceComboBox = new QComboBox();
    QPushButton *startButton = new QPushButton("Start Capture");
    QPushButton *stopButton = new QPushButton("Stop Capture");

    pcap_if_t *alldevs, *device;
    char errbuf[PCAP_ERRBUF_SIZE];
    if (pcap_findalldevs(&alldevs, errbuf) == 0) {
        for (device = alldevs; device; device = device->next) {
            QString devName = device->name;
            QString devDesc = device->description ? device->description : "No description";
            deviceComboBox->addItem(devName + " - " + devDesc, devName);
        }
        pcap_freealldevs(alldevs);
    }

    connect(startButton, &QPushButton::clicked, [this, deviceComboBox]() {
        startAnalysis(deviceComboBox->currentData().toString());
    });
    connect(stopButton, &QPushButton::clicked, this, &TrafficAnalyzer::stopAnalysis);

    controlLayout1->addWidget(new QLabel("Network Device:"));
    controlLayout1->addWidget(deviceComboBox);
    controlLayout1->addWidget(startButton);
    controlLayout1->addWidget(stopButton);

    QHBoxLayout *controlLayout2 = new QHBoxLayout();
    timeWindowSpinBox = new QSpinBox();

    timeWindowSpinBox->setRange(10, 3600);
    timeWindowSpinBox->setValue(60);
    timeWindowSpinBox->setSuffix(" seconds");
    connect(timeWindowSpinBox, QOverload<int>::of(&QSpinBox::valueChanged), this, &TrafficAnalyzer::setTimeWindow);

    controlLayout2->addWidget(new QLabel("Time Window:"));
    controlLayout2->addWidget(timeWindowSpinBox);
    controlLayout2->addStretch();

    mainLayout->addLayout(controlLayout1);
    mainLayout->addLayout(controlLayout2);

    tabWidget = new QTabWidget();

    QWidget *timeSeriesTab = new QWidget();
    QVBoxLayout *timeSeriesLayout = new QVBoxLayout(timeSeriesTab);
    timeSeriesChartView = new QChartView();
    timeSeriesChartView->setRenderHint(QPainter::Antialiasing);
    timeSeriesLayout->addWidget(timeSeriesChartView);
    tabWidget->addTab(timeSeriesTab, "Time Series");

    QWidget *ipTab = new QWidget();
    QVBoxLayout *ipLayout = new QVBoxLayout(ipTab);
    topIPsChartView = new QChartView();
    topIPsChartView->setRenderHint(QPainter::Antialiasing);
    ipLayout->addWidget(topIPsChartView);
    tabWidget->addTab(ipTab, "Top IPs");

    QWidget *summaryTab = new QWidget();
    QVBoxLayout *summaryLayout = new QVBoxLayout(summaryTab);
    statsTableView = new QTableView();
    statsModel = new QStandardItemModel(0, 2, this);
    statsModel->setHeaderData(0, Qt::Horizontal, "Statistic");
    statsModel->setHeaderData(1, Qt::Horizontal, "Value");
    statsTableView->setModel(statsModel);
    statsTableView->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    summaryLayout->addWidget(statsTableView);
    tabWidget->addTab(summaryTab, "Summary");

    QWidget *connectionTab = new QWidget();
    QVBoxLayout *connectionLayout = new QVBoxLayout(connectionTab);
    connectionTableView = new QTableView();
    // 修改：将connectionModel的列数从7减少到6，移除Protocol列
    connectionModel = new QStandardItemModel(0, 6, this);
    connectionModel->setHeaderData(0, Qt::Horizontal, "Source");
    connectionModel->setHeaderData(1, Qt::Horizontal, "Source Port");
    connectionModel->setHeaderData(2, Qt::Horizontal, "Destination");
    connectionModel->setHeaderData(3, Qt::Horizontal, "Dest Port");
    // 删除了Protocol列
    connectionModel->setHeaderData(4, Qt::Horizontal, "Bytes");
    connectionModel->setHeaderData(5, Qt::Horizontal, "First Seen");
    connectionTableView->setModel(connectionModel);
    connectionTableView->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    connectionLayout->addWidget(connectionTableView);
    tabWidget->addTab(connectionTab, "Connections");

    mainLayout->addWidget(tabWidget);

    QHBoxLayout *statusLayout = new QHBoxLayout();
    statusLabel = new QLabel("Ready");
    statusLayout->addWidget(statusLabel);
    mainLayout->addLayout(statusLayout);
}

void TrafficAnalyzer::setupCharts()
{
    timeSeriesChart = new QChart();
    timeSeriesChart->setTitle("Traffic Time Series");
    bytesSeries = new QLineSeries();
    bytesSeries->setName("Bytes per Second");
    bytesSeries->setColor(QColor(52, 152, 219));
    timeSeriesChart->addSeries(bytesSeries);

    yAxisBytes = new QValueAxis();
    yAxisBytes->setTitleText("Bytes per Second");
    yAxisBytes->setLabelFormat("%d");
    yAxisBytes->setGridLineVisible(true);

    xAxisTime = new QDateTimeAxis();
    xAxisTime->setTitleText("Time");
    xAxisTime->setFormat("hh:mm:ss");
    xAxisTime->setGridLineVisible(true);

    timeSeriesChart->setAxisX(xAxisTime, bytesSeries);
    timeSeriesChart->setAxisY(yAxisBytes, bytesSeries);
    timeSeriesChartView->setChart(timeSeriesChart);

    topIPsChart = new QChart();
    topIPsChart->setTitle("Top Communicating IPs");
    topIPsSeries = new QBarSeries();

    yAxisIPs = new QValueAxis();
    yAxisIPs->setTitleText("Bytes");
    yAxisIPs->setLabelFormat("%d");
    yAxisIPs->setGridLineVisible(true);

    xAxisIPs = new QBarCategoryAxis();
    xAxisIPs->setTitleText("IP Address");

    topIPsChart->addSeries(topIPsSeries);
    topIPsChart->setAxisX(xAxisIPs, topIPsSeries);
    topIPsChart->setAxisY(yAxisIPs, topIPsSeries);
    topIPsChartView->setChart(topIPsChart);
}

void TrafficAnalyzer::resetAnalysis()
{
    trafficHistory.clear();
    ipStats.clear();
    connections.clear();

    bytesSeries->clear();
    topIPsSeries->clear();

    connectionModel->removeRows(0, connectionModel->rowCount());
    statsModel->removeRows(0, statsModel->rowCount());

    statsModel->insertRow(0);
    statsModel->setData(statsModel->index(0, 0), "Start Time");
    statsModel->setData(statsModel->index(0, 1), analysisStartTime.toString("yyyy-MM-dd hh:mm:ss"));

    statsModel->insertRow(1);
    statsModel->setData(statsModel->index(1, 0), "Total Packets");
    statsModel->setData(statsModel->index(1, 1), "0");

    statsModel->insertRow(2);
    statsModel->setData(statsModel->index(2, 0), "Total Bytes");
    statsModel->setData(statsModel->index(2, 1), "0");

    statsModel->insertRow(3);
    statsModel->setData(statsModel->index(3, 0), "Capture Duration");
    statsModel->setData(statsModel->index(3, 1), "0 seconds");

    statsModel->insertRow(4);
    statsModel->setData(statsModel->index(4, 0), "Active Connections");
    statsModel->setData(statsModel->index(4, 1), "0");

    statusLabel->setText("Analysis reset");
}

void TrafficAnalyzer::updateCharts()
{
    updateTimeSeriesChart();
    updateTopIPsChart();
    updateStatsTable();
    updateConnectionStats();
}

void TrafficAnalyzer::updateTimeSeriesChart()
{
    bytesSeries->clear();
    if (trafficHistory.isEmpty()) return;

    QMap<QDateTime, qint64> bytesPerSecond;
    for (const auto &traffic : trafficHistory) {
        QDateTime second = traffic.timestamp;
        second = second.addMSecs(-second.time().msec());
        bytesPerSecond[second] += traffic.bytes;
    }

    for (auto it = bytesPerSecond.begin(); it != bytesPerSecond.end(); ++it) {
        bytesSeries->append(it.key().toMSecsSinceEpoch(), it.value());
    }

    if (!bytesPerSecond.isEmpty()) {
        QDateTime minTime = bytesPerSecond.firstKey();
        QDateTime maxTime = bytesPerSecond.lastKey();
        xAxisTime->setRange(minTime, maxTime);

        qint64 maxBytes = 0;
        for (auto value : bytesPerSecond)
            maxBytes = std::max(maxBytes, value);  // 使用std::max自动处理类型
        yAxisBytes->setRange(0, maxBytes * 1.1);
    }
}

void TrafficAnalyzer::updateTopIPsChart()
{
    topIPsSeries->clear();
    QList<IPSummary> sortedIPs;
    for (const auto &ip : ipStats) sortedIPs.append(ip);

    std::sort(sortedIPs.begin(), sortedIPs.end(), [](const IPSummary &a, const IPSummary &b) {
        return (a.sentBytes + a.receivedBytes) > (b.sentBytes + b.receivedBytes);
    });

    int count = qMin(10, sortedIPs.size());
    QBarSet *set = new QBarSet("Bytes");
    QStringList categories;

    for (int i = 0; i < count; i++) {
        set->append(sortedIPs[i].sentBytes + sortedIPs[i].receivedBytes);
        categories << sortedIPs[i].address;
    }

    topIPsSeries->append(set);
    xAxisIPs->clear();
    xAxisIPs->append(categories);

    if (!sortedIPs.isEmpty()) {
        qint64 maxBytes = 0;
        for (int i = 0; i < count; i++) {
            // 将结果转换为qint64后再比较
            maxBytes = std::max(maxBytes, static_cast<qint64>(sortedIPs[i].sentBytes + sortedIPs[i].receivedBytes));
        }
        yAxisIPs->setRange(0, maxBytes * 1.1);
    }
}

void TrafficAnalyzer::updateStatsTable()
{
    qint64 totalBytes = 0, totalPackets = 0;
    for (const auto &traffic : trafficHistory) {
        totalBytes += traffic.bytes;
        totalPackets += traffic.packets;
    }

    statsModel->setData(statsModel->index(0, 1), analysisStartTime.toString("yyyy-MM-dd hh:mm:ss"));
    statsModel->setData(statsModel->index(1, 1), QString::number(totalPackets));
    statsModel->setData(statsModel->index(2, 1), QString::number(totalBytes));

    int elapsed = analysisStartTime.secsTo(QDateTime::currentDateTime());
    statsModel->setData(statsModel->index(3, 1), QString("%1 seconds").arg(elapsed));
    statsModel->setData(statsModel->index(4, 1), QString::number(connections.size()));
}

void TrafficAnalyzer::updateConnectionStats()
{
    connectionModel->removeRows(0, connectionModel->rowCount());
    std::sort(connections.begin(), connections.end(), [](const ConnectionStats &a, const ConnectionStats &b) {
        return a.bytes > b.bytes;
    });

    for (const auto &conn : connections) {
        int row = connectionModel->rowCount();
        connectionModel->insertRow(row);
        connectionModel->setData(connectionModel->index(row, 0), conn.srcIP);
        connectionModel->setData(connectionModel->index(row, 1), conn.srcPort);
        connectionModel->setData(connectionModel->index(row, 2), conn.dstIP);
        connectionModel->setData(connectionModel->index(row, 3), conn.dstPort);
        // 删除了Protocol列的设置
        connectionModel->setData(connectionModel->index(row, 4), conn.bytes);
        connectionModel->setData(connectionModel->index(row, 5), conn.firstSeen.toString("yyyy-MM-dd hh:mm:ss"));
    }
}

QString TrafficAnalyzer::getProtocolName(u_short etherType, u_char ipProtocol)
{
    if (etherType == 0x0800) {
        switch (ipProtocol) {
            case IPPROTO_TCP: return "TCP";
            case IPPROTO_UDP: return "UDP";
            case IPPROTO_ICMP: return "ICMP";
            default: return QString("IP (%1)").arg(ipProtocol);
        }
    } else if (etherType == 0x0806) {
        return "ARP";
    } else if (etherType == 0x86DD) {
        return "IPv6";
    } else {
        return QString("Unknown (0x%1)").arg(etherType, 4, 16, QChar('0')).toUpper();
    }
}

QString TrafficAnalyzer::getIPAddress(const u_char *ip)
{
    return QString("%1.%2.%3.%4").arg(ip[0]).arg(ip[1]).arg(ip[2]).arg(ip[3]);
}

void TrafficAnalyzer::setTimeWindow(int seconds)
{
    timeWindowSeconds = seconds;
    QDateTime windowStart = QDateTime::currentDateTime().addSecs(-timeWindowSeconds);
    while (!trafficHistory.isEmpty() && trafficHistory.first().timestamp < windowStart) {
        trafficHistory.removeFirst();
    }
    updateCharts();
}

void TrafficAnalyzer::setCurrentDevice(const QString &device)
{
    m_currentDevice = device;
}

void TrafficAnalyzer::startAnalysis(const QString &device)
{
    if (isAnalyzing) return;

    // 保存当前设备
    setCurrentDevice(device);

    char errbuf[PCAP_ERRBUF_SIZE];
    m_handle = pcap_open_live(device.toUtf8().constData(), BUFSIZ, 1, 1000, errbuf);
    if (!m_handle) {
        QMessageBox::critical(this, "Error", QString("Could not open device: %1").arg(errbuf));
        return;
    }

    m_captureThread = new CaptureThread(m_handle, this);
    connect(m_captureThread, &CaptureThread::packetCaptured, this, &TrafficAnalyzer::onPacketCaptured);
    m_captureThread->start();

    isAnalyzing = true;
    analysisStartTime = QDateTime::currentDateTime();
    updateTimer->start(1000);

    statusLabel->setText(QString("Capturing on %1").arg(device));
}

void TrafficAnalyzer::stopAnalysis()
{
    if (!isAnalyzing) return;

    isAnalyzing = false;
    updateTimer->stop();

    if (m_captureThread) {
        m_captureThread->stopCapture();
        m_captureThread->wait();
        delete m_captureThread;
        m_captureThread = nullptr;
    }

    if (m_handle) {
        pcap_close(m_handle);
        m_handle = nullptr;
    }

    statusLabel->setText("Capture stopped");
}

void TrafficAnalyzer::processPacket(const struct pcap_pkthdr *header, const u_char *data)
{
    if (!isAnalyzing) return;
    analyzePacket(header, data);
}

void TrafficAnalyzer::analyzePacket(const struct pcap_pkthdr *header, const u_char *data)
{
    QDateTime timestamp = QDateTime::fromSecsSinceEpoch(header->ts.tv_sec);

    if (header->len < sizeof(ether_header)) return;

    const ether_header *eth = reinterpret_cast<const ether_header*>(data);
    u_short etherType = ntohs(eth->ether_type);
    QString protocol = getProtocolName(etherType, 0);

    QString srcIP, dstIP;
    int srcPort = 0, dstPort = 0;
    u_char ipProtocol = 0;

    if (etherType == 0x0800) {
        if (header->len < sizeof(ether_header) + sizeof(ip_header)) return;

        const ip_header *iph = reinterpret_cast<const ip_header*>(data + sizeof(ether_header));
        ipProtocol = iph->proto;
        srcIP = getIPAddress(reinterpret_cast<const u_char*>(&iph->saddr));
        dstIP = getIPAddress(reinterpret_cast<const u_char*>(&iph->daddr));

        protocol = getProtocolName(0, ipProtocol);

        if (ipProtocol == IPPROTO_TCP) {
            if (header->len >= sizeof(ether_header) + (iph->ver_ihl & 0x0F) * 4 + sizeof(tcp_header)) {
                const tcp_header *tcph = reinterpret_cast<const tcp_header*>(data + sizeof(ether_header) + (iph->ver_ihl & 0x0F) * 4);
                srcPort = ntohs(tcph->th_sport);
                dstPort = ntohs(tcph->th_dport);
            }
        } else if (ipProtocol == IPPROTO_UDP) {
            if (header->len >= sizeof(ether_header) + (iph->ver_ihl & 0x0F) * 4 + sizeof(udp_header)) {
                const udp_header *udph = reinterpret_cast<const udp_header*>(data + sizeof(ether_header) + (iph->ver_ihl & 0x0F) * 4);
                srcPort = ntohs(udph->uh_sport);
                dstPort = ntohs(udph->uh_dport);
            }
        }
    }

    if (!srcIP.isEmpty()) {
        if (ipStats.contains(srcIP)) {
            ipStats[srcIP].sentBytes += header->len;
            ipStats[srcIP].sentPackets++;
        } else {
            IPSummary summary;
            summary.address = srcIP;
            summary.sentBytes = header->len;
            summary.receivedBytes = 0;
            summary.sentPackets = 1;
            summary.receivedPackets = 0;
            ipStats[srcIP] = summary;
        }
    }

    if (!dstIP.isEmpty()) {
        if (ipStats.contains(dstIP)) {
            ipStats[dstIP].receivedBytes += header->len;
            ipStats[dstIP].receivedPackets++;
        } else {
            IPSummary summary;
            summary.address = dstIP;
            summary.sentBytes = 0;
            summary.receivedBytes = header->len;
            summary.sentPackets = 0;
            summary.receivedPackets = 1;
            ipStats[dstIP] = summary;
        }
    }

    if (!srcIP.isEmpty() && !dstIP.isEmpty() && (srcPort > 0 || dstPort > 0)) {
        bool connectionExists = false;
        for (auto &conn : connections) {
            if ((conn.srcIP == srcIP && conn.dstIP == dstIP && conn.srcPort == srcPort && conn.dstPort == dstPort) ||
                (conn.srcIP == dstIP && conn.dstIP == srcIP && conn.srcPort == dstPort && conn.dstPort == srcPort)) {
                conn.bytes += header->len;
                conn.packets++;
                conn.lastSeen = timestamp;
                connectionExists = true;
                break;
            }
        }

        if (!connectionExists) {
            ConnectionStats conn;
            conn.srcIP = srcIP;
            conn.srcPort = srcPort;
            conn.dstIP = dstIP;
            conn.dstPort = dstPort;
            // 删除了Protocol字段的设置
            conn.bytes = header->len;
            conn.packets = 1;
            conn.firstSeen = timestamp;
            conn.lastSeen = timestamp;
            connections.append(conn);
        }
    }

    TrafficStats traffic;
    traffic.timestamp = timestamp;
    traffic.bytes = header->len;
    traffic.packets = 1;
    traffic.protocol = protocol;
    traffic.source = srcIP;
    traffic.destination = dstIP;
    trafficHistory.append(traffic);

    QDateTime windowStart = timestamp.addSecs(-timeWindowSeconds);
    while (!trafficHistory.isEmpty() && trafficHistory.first().timestamp < windowStart) {
        trafficHistory.removeFirst();
    }
}

void TrafficAnalyzer::onPacketCaptured(const struct pcap_pkthdr *header, const u_char *data)
{
    processPacket(header, data);
}
