#ifndef TRAFFICANALYZER_H
#define TRAFFICANALYZER_H

#include <QWidget>
#include <QtCharts/QChartView>
#include <QtCharts/QLineSeries>
#include <QtCharts/QBarSeries>
#include <QtCharts/QDateTimeAxis>
#include <QtCharts/QValueAxis>
#include <QtCharts/QBarCategoryAxis>
#include <QStandardItemModel>
#include <QTableView>
#include <QPushButton>
#include <QComboBox>
#include <QSpinBox>
#include <QTimer>
#include <QDateTime>
#include <QMap>
#include <pcap.h>
#include <QTabWidget>
#include <QLabel>
#include <QThread>

QT_CHARTS_USE_NAMESPACE

struct TrafficStats {
    QDateTime timestamp;
    int bytes;
    int packets;
    QString protocol;
    QString source;
    QString destination;
};

struct IPSummary {
    QString address;
    int sentBytes;
    int receivedBytes;
    int sentPackets;
    int receivedPackets;
};

struct ConnectionStats {
    QString srcIP;
    int srcPort;
    QString dstIP;
    int dstPort;
    // QString protocol;  // 移除Protocol字段
    int bytes;
    int packets;
    QDateTime firstSeen;
    QDateTime lastSeen;
};

class CaptureThread : public QThread
{
    Q_OBJECT

public:
    CaptureThread(pcap_t *handle, QObject *parent = nullptr);
    ~CaptureThread();
    void stopCapture();

protected:
    void run() override;

signals:
    void packetCaptured(const struct pcap_pkthdr *header, const u_char *data);

private:
    pcap_t *m_handle;
    bool m_running;
};

class TrafficAnalyzer : public QWidget
{
    Q_OBJECT

public:
    explicit TrafficAnalyzer(QWidget *parent = nullptr);
    ~TrafficAnalyzer();

    void startAnalysis(const QString &device);
    void stopAnalysis();
    void resetAnalysis();
    void processPacket(const struct pcap_pkthdr *header, const u_char *data);

private slots:
    void updateCharts();
    void setTimeWindow(int seconds);
    void onPacketCaptured(const struct pcap_pkthdr *header, const u_char *data);

private:
    void setupUI();
    void setupCharts();
    void analyzePacket(const struct pcap_pkthdr *header, const u_char *data);
    void updateTimeSeriesChart();
    void updateTopIPsChart();
    void updateStatsTable();
    void updateConnectionStats();
    QString getProtocolName(u_short etherType, u_char ipProtocol);
    QString getIPAddress(const u_char *ip);
    QString m_currentDevice;
    void setCurrentDevice(const QString &device);

    QTabWidget *tabWidget;
    QChartView *timeSeriesChartView;
    QChartView *topIPsChartView;
    QTableView *statsTableView;
    QTableView *connectionTableView;
    QSpinBox *timeWindowSpinBox;
    QLabel *statusLabel;

    QChart *timeSeriesChart;
    QChart *topIPsChart;
    QLineSeries *bytesSeries;
    QDateTimeAxis *xAxisTime;
    QValueAxis *yAxisBytes;
    QBarSeries *topIPsSeries;
    QBarCategoryAxis *xAxisIPs;
    QValueAxis *yAxisIPs;

    QStandardItemModel *statsModel;
    QStandardItemModel *connectionModel;

    pcap_t *m_handle;
    bool isAnalyzing;
    QDateTime analysisStartTime;
    QTimer *updateTimer;
    CaptureThread *m_captureThread;

    QList<TrafficStats> trafficHistory;
    QMap<QString, IPSummary> ipStats;
    QList<ConnectionStats> connections;

    int timeWindowSeconds;
};

#endif // TRAFFICANALYZER_H
