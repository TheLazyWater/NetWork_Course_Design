#ifndef DATAPACKAGE_H
#define DATAPACKAGE_H
#include <QString>
#include "Format.h"


class DataPackage
{
private:
    u_int data_length; // data pakage length
    QString timeStamp; // timestamp of package
    QString info;      // a breif introduction of package
    int packageType;   // type

public:
    const u_char *pkt_content; // root pointer of package data

protected:
    /*
     * turn the byteArray to QString
    */
    static QString byteToHex(u_char*str,int size);
public:
    // Construction and destruction
    DataPackage();
    ~DataPackage() = default;

    // set the var
    void setDataLength(unsigned int length);                    // set the package length
    void setTimeStamp(QString timeStamp);                       // set timestamp
    void setPackageType(int type);                              // set package type
    void setPackagePointer(const u_char *pkt_content,int size); // set package pointer
    void setPackageInfo(QString info);                          // set package information

    // get the var
    QString getDataLength();                  // get package length
    QString getTimeStamp();                   // get timestamp
    QString getPackageType();                 // get package type
    QString getInfo();                        // get a breif package information
    QString getSource();                      // get the source address of package
    QString getDestination();                 // get the destination address of package
};

#endif // DATAPACKAGE_H
