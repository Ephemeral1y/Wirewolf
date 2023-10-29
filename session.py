from scapy.all import *
import tkinter as tk
from tkinter import ttk
from ttkbootstrap import Style
import ttkbootstrap as ttkb


class SessionGUI:
    def __init__(self, session_root, style, packets, flag):
        # 初始化GUI，传入数据包和标志指示会话类型（以太网或IP）
        self.root = session_root
        self.style = Style(theme="darkly")
        self.style = style
        self.flag = flag
        self.style.theme_use()
        self.root.update_idletasks()
        self.packets = packets

        # 定义columns为类属性
        self.columns = ['源地址A', '目标地址B', '数据包数', '字节', '数据包A->B', '数据包B->A', '字节A->B', '字节B->A']
        self.sort_states = {col: 0 for col in self.columns}  # 使用self.columns

        # theme_name = self.style.theme_use()
        # print(theme_name)
        # ttk.Style().theme_use(theme_name)
        title = '以太网对话' if flag == 1 else 'IP对话'
        self.root.title(title)
        self.root.geometry('800x400')
        self.session_frame = tk.Frame(self.root, relief='sunken')
        self.session_frame.place(x=10, y=0, width=780, height=390)
        self.show_details()

    def show_details(self):
        # 创建并显示一个Treeview小部件以显示数据包详细信息
        scrollbar = ttkb.Scrollbar(self.session_frame, bootstyle="info")
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        columns = ['源地址A', '目标地址B', '数据包数', '字节', '数据包A->B', '数据包B->A', '字节A->B', '字节B->A']
        self.table = ttk.Treeview(
            master=self.session_frame,
            height=18,
            columns=columns,
            show='headings',
            yscrollcommand=scrollbar.set
        )
        scrollbar['command'] = self.table.yview
        self.setup_columns(self.columns)
        self.table.place(relx=0, rely=0)
        self.populate_table()

    def setup_columns(self, columns):
        # 配置Treeview小部件的列
        for col in columns:
            self.table.heading(col, text=col, command=lambda _col=col: self.treeview_sort_column(_col, False))
            self.table.column(col, width=self.get_column_width(col), minwidth=self.get_column_width(col), anchor=tk.S)

    def treeview_sort_column(self, col, reverse):
        # 检查列的当前状态
        if self.sort_states[col] == 0:  # 默认状态
            # 以升序排序
            self.sort_column_by_value(col, False)
            # 更新列标题以显示升序的上三角形
            self.table.heading(col, text=col + ' ▲', command=lambda: self.treeview_sort_column(col, not reverse))
            # 更新列的排序状态
            self.sort_states[col] = 1
        elif self.sort_states[col] == 1:  # 升序
            # 以降序排序
            self.sort_column_by_value(col, True)
            # 更新列标题以显示降序的下三角形
            self.table.heading(col, text=col + ' ▼', command=lambda: self.treeview_sort_column(col, not reverse))
            # 更新列的排序状态
            self.sort_states[col] = 2
        else:  # 降序
            # 恢复到默认顺序（可能是插入时的顺序，或其他顺序）
            # 如果有特定的默认顺序，请在这部分进行自定义
            self.table.delete(*self.table.get_children())  # 清空表格
            self.populate_table()  # 重新填充表格
            # 更新列标题以删除三角形
            self.table.heading(col, text=col, command=lambda: self.treeview_sort_column(col, False))
            # 重置列的排序状态
            self.sort_states[col] = 0

    def sort_column_by_value(self, col, reverse):
        # 通过值对Treeview列进行排序
        l = [(self.table.set(k, col), k) for k in self.table.get_children('')]

        # 检查列是否应按数字排序
        if col in ('数据包数', '字节', '数据包A->B', '数据包B->A', '字节A->B', '字节B->A'):
            try:
                l.sort(key=lambda t: int(t[0]), reverse=reverse)
            except ValueError:  # 处理可能的值错误
                l.sort(reverse=reverse)
        else:
            l.sort(reverse=reverse)

        for index, (val, k) in enumerate(l):
            self.table.move(k, '', index)

    def get_column_width(self, column):
        # 为每一列设置宽度
        if column in ('源地址A', '目标地址B'):
            return 135
        elif column in ('数据包数', '字节'):
            return 60
        else:
            return 90

    def populate_table(self):
        # 处理数据包并用相关信息填充Treeview小部件
        packets_dict = {}
        show_list = []
        keys_to_delete = []

        for packet in self.packets:
            address_a, address_b, packet_number, packet_bytes = self.extract_packet_info(packet)
            key = f"{address_a}-{address_b}"

            if key not in packets_dict:
                packets_dict[key] = [packet_number, packet_bytes]
            else:
                packets_dict[key][0] += packet_number
                packets_dict[key][1] += packet_bytes

        for key, value in packets_dict.items():
            if key in keys_to_delete:
                continue

            address_a, address_b = key.split('-')
            rev_key = f"{address_b}-{address_a}"

            if rev_key in packets_dict:
                packets_number = value[0] + packets_dict[rev_key][0]
                packets_bytes = value[1] + packets_dict[rev_key][1]
                packet_a2b = value[0]
                packet_b2a = packets_dict[rev_key][0]
                bytes_a2b = value[1]
                bytes_b2a = packets_dict[rev_key][1]
                show_list.append([address_a, address_b, packets_number, packets_bytes, packet_a2b, packet_b2a, bytes_a2b,
                                  bytes_b2a])
                keys_to_delete.extend([key, rev_key])
            else:
                packets_number = value[0]
                packets_bytes = value[1]
                packet_a2b = packets_number
                packet_b2a = 0
                bytes_a2b = packets_bytes
                bytes_b2a = 0
                show_list.append([address_a, address_b, packets_number, packets_bytes, packet_a2b, packet_b2a, bytes_a2b,
                                  bytes_b2a])
                keys_to_delete.append(key)

        for i in show_list:
            self.table.insert('', tk.END, values=i)

    def extract_packet_info(self, packet):
        # 根据会话类型（以太网或IP）从数据包中提取相关信息
        if self.flag == 1:  # 以太网会话
            address_a = packet.src
            address_b = packet.dst
        else:  # IP会话
            if IP in packet:
                address_a = packet[IP].src
                address_b = packet[IP].dst
            else:
                address_a = address_b = None

        packet_number = 1
        packet_bytes = len(packet) if address_a and address_b else 0

        return address_a, address_b, packet_number, packet_bytes
