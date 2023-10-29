from scapy.all import *
from tkinter import *
import tkinter as tk
from tkinter.ttk import *
import tkinter.messagebox 
from ttkbootstrap.dialogs import Messagebox
import tkinter.font as tkFont

class TrackTcpGUI:
    def __init__(self, packets, selected_packet):
        self.root = Tk()
        self.root.title('流信息')
        self.root.geometry('1000x400')
        self.frame_info = tk.Frame(self.root, bd=5, relief='sunken')
        self.frame_info.place(x=10, y=0, width=980, height=200,)
        self.frame_hex = tk.Frame(self.root, bd=5, relief='sunken')
        self.frame_hex.place(x=10, y=205, width=980, height=190,)
        self.packets = packets
        self.selected_packet = selected_packet
        self.create_table()
        self.create_hex_content()

        # 定义列排序状态
        self.columns = ['序号', '源地址', '目标地址', '源端口', '目标端口', '协议', '长度']
        self.sort_states = {col: 0 for col in self.columns}

    def create_table(self):
        columns = ['序号', '源地址', '目标地址', '源端口', '目标端口', '协议', '长度']
        scrollbar = Scrollbar(self.frame_info)
        scrollbar.pack(side=RIGHT, fill=Y)
        self.table = Treeview(
            master=self.frame_info,
            height=8,
            columns=columns,
            show='headings',
            yscrollcommand=scrollbar.set
        )
        scrollbar['command'] = self.table.yview

        self.table.bind("<<TreeviewSelect>>", self.update_hex_view)
        for col in columns:
            self.table.heading(column=col, text=col, command=lambda _col=col: self.treeview_sort_column(_col, False))
        self.set_column_properties()
        self.table.place(relx=0, rely=0)
        self.display_packet_info()

    def set_column_properties(self):
        column_widths = {'序号': 67, '源地址': 150, '目标地址': 120, '源端口': 120, '目标端口': 90, '协议': 80, '长度': 300}
        for col, width in column_widths.items():
            self.table.column(col, width=width, minwidth=width, anchor='center')

    def display_packet_info(self):
        show_list = []
        if IP in self.selected_packet:
            src = self.selected_packet[IP].src
            dst = self.selected_packet[IP].dst
        else:
            src = self.selected_packet.src
            dst = self.selected_packet.dst
        protocol = 'TCP'
        try:
            sport = self.selected_packet['TCP'].sport
            dport = self.selected_packet['TCP'].dport
        except:
            Messagebox.ok(message="请选择TCP包", title="提示", alert=False)
            return
        for index, packet in enumerate(self.packets):
            try:
                if packet['TCP']:
                    if IP in packet:
                        src_i = packet[IP].src
                        dst_i = packet[IP].dst
                    else:
                        src_i = packet.src
                        dst_i = packet.dst
                    if (packet['TCP'].sport == sport and packet['TCP'].dport == dport and src_i == src and dst_i == dst):
                        show_list.append([index, src_i, dst_i, sport, dport, 'TCP', (len(packet)), str(packet.summary())])
                    elif (packet['TCP'].sport == dport and packet['TCP'].dport == sport and src_i == dst and dst_i == src):
                        show_list.append([index, src_i, dst_i, dport, sport, 'TCP', (len(packet)), str(packet.summary())])
            except:
                continue
        for packet_info in show_list:
            self.table.insert('', END, values=packet_info)

    def treeview_sort_column(self, col, reverse):
        # 获取选中列的值和索引
        l = [(self.table.set(k, col), k) for k in self.table.get_children('')]

        # 根据列的类型进行排序
        if col in ('序号', '源端口', '目标端口', '长度'):
            try:
                l.sort(key=lambda t: int(t[0]), reverse=reverse)
            except ValueError:
                l.sort(reverse=reverse)
        else:
            l.sort(reverse=reverse)

        for index, (val, k) in enumerate(l):
            self.table.move(k, '', index)

        # 切换排序顺序并更新列标题文本
        if reverse:
            self.table.heading(col, text=col + ' ▼', command=lambda: self.treeview_sort_column(col, not reverse))
        else:
            self.table.heading(col, text=col + ' ▲', command=lambda: self.treeview_sort_column(col, not reverse))

        # 如果第三次点击，则重置排序状态为默认状态
        if self.sort_states[col] == 2:
            self.sort_states[col] = 0
            self.table.heading(col, text=col, command=lambda: self.treeview_sort_column(col, False))
        else:
            self.sort_states[col] += 1


    def create_hex_content(self):
        self.hex_text = Text(self.frame_hex, width=157, height=14)
        self.hex_text.place(relx=0, rely=0)
        font_example = tkFont.Font(size=10)
        self.hex_text.configure(font=font_example)
        scrollbar = Scrollbar(self.frame_hex)
        scrollbar.pack(side=RIGHT, fill=Y)
        self.hex_text['yscrollcommand'] = scrollbar.set
        scrollbar['command'] = self.hex_text.yview

    def update_hex_view(self, event):
        selected_item = self.table.set(self.table.focus())
        print(selected_item)
        selected_packet = self.packets[eval(selected_item['序号'])]
        ethernet_layer = selected_packet.getlayer(0)
        hex_data = hexdump(ethernet_layer, dump=True)

        formatted_hex_data = self.format_hex_dump(hex_data)
        self.hex_text.delete(1.0, END)
        self.hex_text.insert(INSERT, formatted_hex_data)

    def format_hex_dump(self, hex_data):
        # 拆分行并添加前导空格以进行对齐
        lines = hex_data.split('\n')
        formatted_lines = [line[0:] for line in lines]  # 删除初始地址部分
        formatted_hex_data = '\n'.join(formatted_lines)
        return formatted_hex_data
