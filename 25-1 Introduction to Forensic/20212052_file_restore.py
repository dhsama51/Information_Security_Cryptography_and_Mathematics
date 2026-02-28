###20212052 이동훈###
##사용법 1. 20212052_file_restore.py와 "과제용"이라는 이름을 가진 이미지 파일을 같은 디렉터리에 놓습니다.##
##      2. 20212052_file_restore.py를 실행하게 되면 해당 파일이 존재하는 디렉터리에 지워진 파일들이 모두 복구되는 모습을 확인하실 수 있습니다.##

import os

####중요 위치만 전역변수로 선언####
FAT_pos = 0
root_pos = 0

class FAT_reserved_parse:
    def __init__(self, data):
        #기본 정보 계산
        self.jump_boot_code = int.from_bytes(data[0:3], byteorder="little")
        self.oem_name = data[3:11].decode("utf-8")
        self.bytes_per_sector = int.from_bytes(data[11:13], byteorder="little")
        self.sectors_per_cluster = data[13]
        self.reserver_sector_count = int.from_bytes(data[14:16], byteorder="little")
        self.num_of_fat = data[16]
        self.fat_size_32 = int.from_bytes(data[36:40], byteorder="little")
        self.fsinfo_offset = int.from_bytes(data[48:50], byteorder="little")
        self.file_system_type = data[82:90].decode('utf-8').strip(' ')

        self.sect_len = self.bytes_per_sector
        self.clus_len = self.sect_len * self.sectors_per_cluster

    def __repr__(self):
        #출력을 위해 만들어둔 것들
        self.component = ['Jump Boot Code', 'OEM Name', 'Bytes per Sector',
                          'Sectors per cluster', 'Reserver sector count',
                          'Num of FAT', 'FAT Size 32', 'FSINFO offset',
                          'File System Type']
        self.value = [self.jump_boot_code, self.oem_name, self.bytes_per_sector,
                      self.sectors_per_cluster, self.reserver_sector_count,
                      self.num_of_fat, self.fat_size_32, self.fsinfo_offset,
                      self.file_system_type]
        return "\n".join(f"{self.component[i]}: {self.value[i]}" for i in range(9))

class FAT_parse():
    def __init__(self):
        self.cluster, self.next_cluster = [], []
    def parse(self, data):
        i = 8 #0, 1번 클러스터는 예약. 2번째부터 파싱하면 됨
        #클러스터 번호 순으로 확인하되, 연결되는 클러스터가 있으면 거기를 먼저 확인인
        while True:
            #연결되는 클러스터가 없는 경우 -> i+1번 클러스터 확인
            if len(self.next_cluster) == 0:
                value = int.from_bytes(data[i:i+4], 'little')
                if value == 0: #00 00 00 00이 아니면 분석
                    break
                self.cluster.append(i//4)
                i += 4
                if value != 0x0FFFFFFF: # EOF면 next_cluster 없음
                    self.next_cluster.append(value)
            #연결되는 클러스터가 있는 경우 -> 연결되는 클러스터 확인
            else:
                index = self.next_cluster.pop()
                value = int.from_bytes(data[index*4:index*4+4], 'little')
                self.cluster.append(index)
                if value != 0x0FFFFFFF:
                    self.next_cluster.append(value)
    def __repr__(self):
        return f"사용 중인 클러스터 번호: "+", ".join(f"{a}" for a in self.cluster)

class data_parse:
    def __init__(self):
        self.file, self.dir, self.etc = [], [], []
    def SFN_parse(self, data):
        #파일 이름 파싱
        self.filename_bytes = b""
        for i in range(0, 8):
            if data[i] == 0xFF:
                i-=1
                break
        self.filename_bytes += data[0:i+1]
        self.filename=self.filename_bytes.decode('utf-8').strip(' ')

        #기본 정보 계산
        self.attr = data[11]
        self.start_clus = int.from_bytes(data[20:22], byteorder="little") * 256 + int.from_bytes(data[26:28], byteorder="little")
        self.content_pos = (root_pos + (self.start_clus - 2) * 2) * area_1.sect_len
        self.file_size = int.from_bytes(data[28:32], byteorder="little")

        self.create_time = int.from_bytes(data[14:16], byteorder="little")
        self.create_data = int.from_bytes(data[16:18], byteorder="little")
        self.last_access_data = int.from_bytes(data[18:20], byteorder="little")
        self.last_written_time = int.from_bytes(data[22:24], byteorder="little")
        self.last_written_date = int.from_bytes(data[24:26], byteorder="little")
        
        #계산한 값들 반환
        return [self.attr, self.filename, self.content_pos, self.file_size, self.create_time, self.create_data, self.last_access_data, self.last_written_time, self.last_written_date]

    def LFN_parse(self, data):
        #파일 이름 파싱
        self.filename_bytes = b""
        sections = [(1, 11), (14, 26), (28, 32)]
        for start, end in sections:
            for i in range(start, end, 2):
                if data[i] == 0xFF or data[i] == 0x00:
                    i-=2
                    break
            self.filename_bytes += data[start:i+2]
        self.filename=self.filename_bytes.decode('utf-16le')

        #기본 정보 계산
        self.attr = data[43]
        self.start_clus = int.from_bytes(data[52:54], byteorder="little") * 256 + int.from_bytes(data[58:60], byteorder="little")
        self.content_pos = (root_pos + (self.start_clus - 2) * 2) * area_1.sect_len
        self.file_size = int.from_bytes(data[60:64], byteorder="little")
        
        self.create_time = int.from_bytes(data[46:48], byteorder="little")
        self.create_data = int.from_bytes(data[48:50], byteorder="little")
        self.last_access_data = int.from_bytes(data[50:52], byteorder="little")
        self.last_written_time = int.from_bytes(data[54:56], byteorder="little")
        self.last_written_date = int.from_bytes(data[56:58], byteorder="little")
        
        #계산한 값들 반환
        return [self.attr, self.filename, self.content_pos, self.file_size, self.create_time, self.create_data, self.last_access_data, self.last_written_time, self.last_written_date]
    
    def LLFN_parse(self, data):
        #파일 이름 파싱
        self.filename_bytes = b""
        sections = [(33, 43), (46, 58), (60, 64), (1, 11), (14, 26), (28, 32)]
        for start, end in sections:
            for i in range(start, end, 2):
                if data[i] == 0xFF or data[i] == 0x00:
                    i-=2
                    break
            self.filename_bytes += data[start:i+2]
        self.filename=self.filename_bytes.decode('utf-16le')
        
        #기본 정보 계산
        self.attr = data[75]
        self.start_clus = int.from_bytes(data[84:86], byteorder="little") * 256 + int.from_bytes(data[90:92], byteorder="little")
        self.content_pos = (root_pos + (self.start_clus - 2) * 2) * area_1.sect_len
        self.file_size = int.from_bytes(data[92:96], byteorder="little")

        self.create_time = int.from_bytes(data[78:80], byteorder="little")
        self.create_data = int.from_bytes(data[80:82], byteorder="little")
        self.last_access_data = int.from_bytes(data[82:84], byteorder="little")
        self.last_written_time = int.from_bytes(data[86:88], byteorder="little")
        self.last_written_date = int.from_bytes(data[88:90], byteorder="little")
        
        #계산한 값들 반환
        return [self.attr, self.filename, self.content_pos, self.file_size, self.create_time, self.create_data, self.last_access_data, self.last_written_time, self.last_written_date]

    def parse(self, data, dir_index):
        i = 0
        #root 디렉터리의 경우 볼륨 label 부분을 추가로 파싱
        if dir_index == 0:
            if data[11] != 0x08:
                print("root 디렉터리인데 볼륨 label이 적혀 있지 않음");exit(1)
            self.volume_label = data[0:11].decode('ascii')
            i+=32
        
        #클러스터 크기 내에서, 적혀 있는 부분을 만나는 동안 파일, 디렉터리 파싱
        while len(data) > i and data[i:i+16].hex() != "00000000000000000000000000000000":
            #SFN, LFN, LLFN(32byte, 64byte, 96byte) 분류
            size = 32
            if data[i+11] == 0x0F:
                size += 32
                if data[i+43] == 0x0F:
                    size += 32
            
            #위 분류에 따라 파싱 함수 나누어 작성
            if size == 32:
                result = self.SFN_parse(data[i:i+32])
                i += size
            if size == 64:
                result = self.LFN_parse(data[i:i+64])
                i += size
            if size == 96:
                result = self.LLFN_parse(data[i:i+96])
                i += size
            
            #Attribute가 0x20이면 파일, 0x10이면 디렉터리, 그 외이면 버그 수정을 위해 etc로 분류
            if int(result[0]) & 0x20: self.file.append(result)
            elif int(result[0]) & 0x10: self.dir.append(result)
            else: self.etc.append(result)
        #파싱 결과 알게 된 파일, 디렉터리, etc를 반환(디버깅 용도)
        return [self.file, self.dir, self.etc]

    def restore(self, file):
        #파일의 데이터 부분을 읽어와 실제로 복원
        for component in self.file:
            file.seek(component[2])
            restored_data = file.read(component[3])
            with open("./"+component[1], "wb") as file2:
                file2.write(restored_data)
            




########################################main()########################################
file = open("./과제용", "rb")

#이미지 파일에서 FAT 예약 영역 읽어오기
file.seek(0)
data = file.read(96)
#FAT 예약 영역 분석
area_1 = FAT_reserved_parse(data)
print(area_1)


#이미지 파일에서 FAT 영역 읽어오기
FAT_pos = area_1.reserver_sector_count
file.seek(FAT_pos * area_1.sect_len)
data = file.read(area_1.fat_size_32 * area_1.sect_len)
#FAT 영역 분석
area_2 = FAT_parse()
area_2.parse(data)
print(area_2)


#조사하는 디렉터리 순서 기록
dir_index = 0

#이미지 파일에서 root 디렉터리 읽어오기
root_pos = 0 + area_1.reserver_sector_count + 2 * area_1.fat_size_32
file.seek(root_pos * area_1.sect_len)
data = file.read(area_1.clus_len)
root_pos_rest = root_pos + (area_2.cluster[1] - 2) * 2
file.seek(root_pos_rest * area_1.sect_len)
data += file.read(area_1.clus_len)

#root 디렉터리 분석
root = data_parse()
result = root.parse(data, dir_index)
dir_index += 1
print(result[0], "\n")
print(result[1], "\n")
print(result[2], "\n")
root.restore(file)


#이미지 파일에서 test_dir 디렉터리 읽어오기
test_dir_pos = root_pos + (area_2.cluster[5] - 2) * 2
file.seek(test_dir_pos * area_1.sect_len)
data = file.read(area_1.clus_len)
test_dir_pos_rest = root_pos + (area_2.cluster[6] - 2) * 2
file.seek(test_dir_pos_rest * area_1.sect_len)
data += file.read(area_1.clus_len)

#test_dir 디렉터리 분석
test_dir = data_parse()
result = test_dir.parse(data, dir_index)
dir_index += 1
print(result[0], "\n")
print(result[1], "\n")
print(result[2], "\n")
test_dir.restore(file)

file.close()