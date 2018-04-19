# 2016-Network_System

## Summary
2016년 2학기 네트워크 시스템 프로젝트 과제로 제출한 ARP Attack 감지 프로그램입니다. 이 프로그램을 실행하기 위해선 winpcap 라이브러리가 필요합니다. 코드 컴파일을 위한 개발자용 라이브러리 설치는 https://www.winpcap.org/devel.htm, 단순 실행만을 위한 일반인용 라이브러리 설치는 https://www.winpcap.org/install/default.htm 를 참고하십시오. winpcap 라이브러리에 대한 자세한 정보는 http://egloos.zum.com/silverer/v/2107832 에 있습니다.

## ARP
---
Address Resolution Protocol의 약자이며, IP 주소와 MAC 주소를 바인딩시키기 위해 사용되는 네트워크 계층의 프로토콜입니다. 특정 호스트의 IP 주소만 알고 MAC 주소를 모를 경우 IP의 주소와 브로드캐스팅 MAC 주소인 FF:FF:FF:FF:FF:FF를 네트워크 상에 전송하며, 해당 IP를 가진 호스트가 ARP Request 패킷을 받을 경우 자신의 MAC Address를 담은 ARP reply 패킷을 유니캐스트로 전송합니다.

## ARP Storm
---
ARP 패킷은 브로드캐스트 패킷이기 때문에 스위치에서 걸러지지 않습니다. 그렇기 때문에 특정 네트워크를 마비시키기 위해 짧은 시간 동안 엄청난 양의 ARP 패킷을 보내는 공격이 존재하며, 이를 ARP Storm이라 합니다. 이 프로그램의 목적 또한 ARP Storm 공격이 감지되면 이를 저장한 후 사용자에게 알려주기 위함입니다.