from scapy.all import *
from queue import Queue
import os
import sys
import time
from tkinter import *
import tkinter as tk
from tkinter import ttk
import tkinter.messagebox
import tkinter.font as tkFont
from scapy.arch.common import compile_filter
from ttkbootstrap import Style
from ttkbootstrap.constants import *
import ttkbootstrap as ttkb
from ttkbootstrap.dialogs import Messagebox
from tkinter import Tk, simpledialog
from tkinter.filedialog import asksaveasfilename
from tkinter.filedialog import askopenfilename
from session import SessionGUI
from track_tcp import TrackTcpGUI


class WirewolfUI:
    def __init__(self, root):
        # 初始化UI界面
        self.root = root
        self.style = Style(theme="darkly")
        # print(self.style)
        self.style.theme_use()
        self.root.title('Wirewolf')
        self.root.geometry('900x600')

        # print(self.style.theme_names())
        # style.theme_use("cosmo")

        # 创建不同功能区域的框架
        self.header_frame = self.create_frame(self.root, 10, 0, 880, 100)
        self.stats_frame = self.create_frame(self.root, 10, 100, 880, 150)
        self.analysis = self.create_frame(self.root, 10, 260, 880, 180)
        self.details = self.create_frame(self.root, 10, 450, 880, 140)

        # 初始化变量
        self.packet_handling = None
        self.packet_queue = Queue()
        self.sniffer = None
        self.packets = []
        self.count = 0
        # 线程默认为5
        self.thread_count = 5 
        # 定义列排序状态
        self.columns = ['序号', '时间', '源地址', '目标地址', '协议', '长度', '信息']
        self.sort_states = {col: 0 for col in self.columns}

        # 创建菜单栏
        self.create_menu_bar()
        
        # 创建过滤器输入框
        self.filter()

        # 创建网卡选择区域
        self.interface()

        # 创建按钮
        self.button()

        # 创建数据包列表
        self.create_packet_list_treeview()

        # 创建协议树
        self.create_tree_layer()

        # 创建十六进制内容显示区域
        self.create_hex_content()

    def create_frame(self, master, x, y, width, height):
        # 创建框架
        frame = tk.Frame(master, bd=5, relief='sunken')
        frame.place(x=x, y=y, width=width, height=height)
        return frame

    def create_menu_bar(self):
        # 创建菜单栏
        mainmenu = tk.Menu(self.root)

        # 文件菜单
        file_menu = tk.Menu(mainmenu, tearoff=False)
        file_menu.add_command(label="介绍", command=self.menuCommand)
        file_menu.add_separator()
        file_menu.add_command(label="打开", command=self.open_packet)
        file_menu.add_separator()
        file_menu.add_command(label="退出", command=self.root.quit)


        # 统计菜单
        stats_menu = tk.Menu(mainmenu, tearoff=False)
        stats_menu.add_command(label="以太网统计", command=self.session)
        stats_menu.add_command(label="IP统计", command=self.session_IP)

        # 分析菜单
        anal_menu = tk.Menu(mainmenu, tearoff=False)
        anal_menu.add_command(label="追踪TCP流", command=self.track_tcp)

        # 设置菜单
        settings_menu = tk.Menu(mainmenu, tearoff=False)
        settings_menu.add_command(label="修改线程数量", command=self.change_thread_count)

        # 主题菜单
        themes_menu = tk.Menu(mainmenu, tearoff=False)
        themes_list = self.style.theme_names()
        for theme_name in themes_list:
            themes_menu.add_command(label=theme_name, command=lambda theme=theme_name: self.change_theme(theme))

        mainmenu.add_cascade(label="文件", menu=file_menu)
        mainmenu.add_cascade(label="统计", menu=stats_menu)
        mainmenu.add_cascade(label="分析", menu=anal_menu)
        mainmenu.add_cascade(label="主题", menu=themes_menu)
        mainmenu.add_cascade(label="设置", menu=settings_menu)

        self.root.config(menu=mainmenu)

    def change_thread_count(self):
        # 使用弹出对话框让用户输入新的线程数量，并在程序中应用该设置
        thread_count = simpledialog.askinteger("修改线程数量", "输入新线程数量:(默认为5)")
        if thread_count is not None:
            # 添加应用线程数量的代码
            Messagebox.ok("修改成功", f"线程数量修改至 {thread_count}")
            print(thread_count)
            self.thread_count = thread_count

    def change_theme(self,theme):
        # 切换主题
        self.style.theme_use(theme)

    def menuCommand(self):
        # 显示关于信息
        Messagebox.ok(message='''
    Wirewolf 网络嗅探器
    Developed by Ephemeral1y
                      ''',title="关于",alert=False)
               

    def session(self):
        # 打开以太网统计窗口
        session_root = tk.Tk()
        SessionGUI(session_root, self.style, self.packets, 1)

    def session_IP(self):
        # 打开IP统计窗口
        session_root = tk.Tk()
        SessionGUI(session_root, self.style, self.packets, 2)

    def track_tcp(self):
        # 追踪TCP流
        itm = self.table.set(self.table.focus())
        print(itm)
        if not itm:
            Messagebox.ok(message="请选择数据包后再追踪流",title="提示",alert=False)
            return
        packet = self.packets[eval(itm['序号']) - 1]
        print(packet)

        TrackTcpGUI(self.packets, packet)

    def filter(self):
        # 创建过滤器输入框
        Dy_String = tk.StringVar()
        self.entry1 = ttkb.Entry(self.header_frame, textvariable=Dy_String,bootstyle="info")
        self.entry1.bind("<FocusOut>", self.check_filter)
        self.entry1.place(relx=0.1, rely=0.6, relwidth=0.7)
        self.label1 = Label(
            self.header_frame,
            text="捕获过滤:",
            font=("微软雅黑", 10),
        )
        self.label1.place(relx=0.01, rely=0.6)

    def check_filter(self, e):
        # 失去焦点时进行验证
        filter_s = self.entry1.get().strip()

        if filter_s == '':
            self.entry1.configure(bootstyle="info")
            return

        try:
            compile_filter(filter_exp=filter_s)
            self.entry1.configure(bootstyle="success")
        except:
            Messagebox.ok(message="请输入正确的过滤器",title="提示",alert=False)
            self.entry1.configure(bootstyle="danger")
            return

    def button(self):
        # 创建按钮
        self.control_button = ttkb.Button(self.header_frame, text="开始抓包", command=self.get_packet,bootstyle="success-outline")  
        self.control_button.place(relx=0.85, rely=0.2, relwidth=0.1)
        # 创建保存抓包按钮
        self.save_button = ttkb.Button(self.header_frame, text="保存抓包", command=self.save_packets,bootstyle="info-outline")
        self.save_button.place(relx=0.85, rely=0.6, relwidth=0.1)

    def interface(self):
        # 网卡选项
        var = StringVar()
        ifaces_list = [face.name for face in get_working_ifaces()]
        # print(ifaces_list)
        self.comb = ttkb.Combobox(self.header_frame, textvariable=var, values=ifaces_list,bootstyle="info")
        self.comb.place(relx=0.1, rely=0.2, relwidth=0.7)
        self.label1 = Label(
            self.header_frame,
            text="网卡选择:",
            font=("微软雅黑", 10),
        )
        self.label1.place(relx=0.01, rely=0.2)

    def choose_iface(self):
        # 获取选择的网卡
        iface_index = self.comb.current()
        if iface_index == -1:  
            return None
        iface = get_working_ifaces()[iface_index]
        print(iface)
        return iface

    def create_packet_list_treeview(self):
        # 创建数据包列表的TreeView
        columns = ['序号', '时间', '源地址', '目标地址', '协议', '长度', '信息']
        yscrollbar = ttkb.Scrollbar(self.stats_frame, bootstyle="info")
        yscrollbar.pack(side=RIGHT, fill=Y)

        self.table = treeview = ttk.Treeview(
            master=self.stats_frame,  
            height=6,  
            columns=columns,  
            show='headings',  
            yscrollcommand=yscrollbar.set)
        
        yscrollbar['command'] = treeview.yview

        treeview.bind("<<TreeviewSelect>>", self.on_select_packet_list)
        treeview.heading(column='序号', text='序号', anchor='center', command=lambda: print('序号'))  
        treeview.heading('时间', text='时间')  
        treeview.heading('源地址', text='源地址')  
        treeview.heading('目标地址', text='目标地址')  
        treeview.heading('协议', text='协议')  
        treeview.heading('长度', text='长度')  
        treeview.heading('信息', text='信息',)  
        treeview.column('序号', width=70, minwidth=70, anchor='center')  
        treeview.column('时间', width=150, minwidth=150, anchor='center')  
        treeview.column('源地址', width=120, minwidth=120, anchor='center')  
        treeview.column('目标地址', width=120, minwidth=120,anchor='center')  
        treeview.column('协议', width=70, minwidth=70, anchor='center')  
        treeview.column('长度', width=70, minwidth=70, anchor='center')  
        treeview.column('信息', width=250, minwidth=250, anchor='center')
        for col in columns:
            self.table.heading(column=col, text=col, command=lambda _col=col: self.treeview_sort_column(_col, False))  
        treeview.place(relx=0, rely=0)

    def treeview_sort_column(self, col, reverse):
        # 获取选中列的值和索引
        l = [(self.table.set(k, col), k) for k in self.table.get_children('')]

        # 根据列的类型进行排序
        if col in ('序号', '源地址', '目标地址', '长度'):
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
    
    def on_select_packet_list(self, e):
        # 选择数据包列表中的项
        itm = self.table.set(self.table.focus())
        print(itm)
        packet = self.packets[eval(itm['序号']) - 1]
        self.packet_handling = packet
        self.update_layer_list(packet)

    def start(self):
        # 启动抓包子进程
        for i in range(self.thread_count):
            T1 = threading.Thread(name='t1', target=self.get_packet, daemon=True)
            T1.start()

    def get_packet(self):
        if self.sniffer:
            self.sniffer.stop()
            self.sniffer = None
            self.control_button.configure(text="继续抓包",bootstyle="info-outline")
            self.count = 0
            return

        iface = self.choose_iface()
        filter_exp = self.entry1.get().strip()
        print(filter_exp)

        if iface is None:
            Messagebox.ok(message="请先选择网卡",title="提示",alert=False)
            return

        self.sniffer = AsyncSniffer(
            iface=iface,
            prn=self.packet_analyse,
            filter=filter_exp,
        )

        # 每次抓包都清空表格
        self.clear_packet_table()

        self.sniffer.start()
        self.control_button.configure(text="暂停抓包",bootstyle="danger-outline")

    def save_packets(self):
        # 保存抓包按钮的点击事件
        if not self.packets:
            Messagebox.ok(message="没有抓到任何数据包", title="提示", alert=False)
            return

        # 提示用户选择保存文件的路径
        file_path = asksaveasfilename(defaultextension=".pcap", filetypes=[("Pcap files", "*.pcap")])
        if not file_path:
            return  # 用户取消保存操作

        # 将抓到的数据包保存到用户指定的文件中
        with PcapWriter(file_path, append=False) as pcap_writer:
            for packet in self.packets:
                pcap_writer.write(packet)

        Messagebox.ok(message="抓包已保存", title="提示", alert=False)
    
    def open_packet(self):
        file_path = askopenfilename(filetypes=[("PCAP files", "*.pcap")])
        if file_path:
            self.load_packets(file_path)

    def load_packets(self, file_path):
        try:
            with PcapReader(file_path) as pcap_reader:
                for packet in pcap_reader:
                    self.packet_analyse(packet)
        except Exception as e:
            Messagebox.ok(message=f"加载数据包出错: {str(e)}", title="错误", alert=False)
    
    
    def clear_packet_table(self):
        # 清空数据包表格
        for item in self.table.get_children():
            self.table.delete(item)

        # 清空协议树
        for item in self.tree_layer.get_children():
            self.tree_layer.delete(item)

        # 清空十六进制内容
        self.hex_text.delete(1.0, END)
        
        self.count = 0
        self.packets = []  

    def packet_analyse(self, packet):
        # 数据包分析
        self.packet_queue.put(packet)
        self.packets.append(packet)  
        self.count += 1
        
        # print(self.thread_count)
        for i in range(self.thread_count):
            T1 = threading.Thread(name='t1', target=self.thread_handle_packet, daemon=True)
            T1.start()

    def thread_handle_packet(self):
        # 处理数据包的线程
        lock = threading.Lock()
        with lock:
            packet = self.packet_queue.get()
            time_show = datetime.fromtimestamp(packet.time).strftime('%Y-%m-%d %H:%M:%S')
            if IP in packet:
                src = packet[IP].src
                dst = packet[IP].dst
            else:
                src = packet.src
                dst = packet.dst
            layer = None
            for var in self.get_packet_layers(packet):
                if not isinstance(var, (Padding, Raw)):
                    layer = var
            if layer.name[0:3] == "DNS":
                protocol = "DNS"
            else:
                protocol = layer.name
            length = f"{len(packet)}"
            try:
                info = str(packet.summary())
            except:
                info = "error"
            show_info = [self.count, time_show, src, dst, protocol, length, info]
            items = self.table.insert('', END, values=show_info)
            self.table.see(items)

    def get_packet_layers(self, packet):
        # 获取数据包的不同层
        counter = 0
        while True:
            layer = packet.getlayer(counter)
            if layer is None:
                break
            yield layer
            counter += 1

    def create_tree_layer(self):
        # 创建协议树
        self.tree_layer = ttk.Treeview(self.analysis, height=8, columns=('#'), show='tree')
        self.tree_layer.column('#0', width=650, stretch=False)
        self.tree_layer.place(relx=0.0, rely=0.0)

        scrollbar = ttkb.Scrollbar(self.analysis,bootstyle="info")
        scrollbar.pack(side=RIGHT, fill=Y)
        self.tree_layer['yscrollcommand'] = scrollbar.set
        scrollbar['command'] = self.tree_layer.yview

        self.tree_layer.bind("<<TreeviewSelect>>", self.on_select_tree_layer)

    def on_select_tree_layer(self, event):
        # 选择协议树的项
        item_id = self.tree_layer.focus()
        try:
            layer_name = self.tree_layer.item(item_id, option='text')
        except:
            return

        packet = self.packet_handling
        counter = 0
        while True:
            layer = packet.getlayer(counter)
            try:
                if layer.name == layer_name:
                    break
                if layer is None:
                    break
                counter += 1
            except:
                return

        self.hex_text.delete(1.0, END)
        self.hex_text.insert(INSERT, hexdump(layer, dump=True))

    def update_layer_list(self, packet):
        # 更新协议树
        for item in self.tree_layer.get_children():
            self.tree_layer.delete(item)

        layer_name = []
        counter = 0
        Ethernet_layer = packet.getlayer(0)
        self.hex_text.delete(1.0, END)
        if Ethernet_layer.name == 'Ethernet':
            self.hex_text.insert(INSERT, hexdump(Ethernet_layer, dump=True))

        while True:
            layer = packet.getlayer(counter)
            if layer is None:
                break
            layer_name.append(layer)
            counter += 1

        parent_child = [0] * len(layer_name)
        for index, layer in enumerate(layer_name):
            parent_child[index] = self.tree_layer.insert("", index, text=layer.name)
            # print(index)
            for name, value in layer.fields.items():
                # print(parent_child[index], index, f"{name}: {value}")
                self.tree_layer.insert(parent_child[index], index, text=f"{name}: {value}")

    def create_hex_content(self):
        # 创建十六进制内容显示区域
        self.hex_text = Text(self.details, width=121, height=9)
        self.hex_text.place(relx=0, rely=0, relwidth=1, relheight=1)  # 使十六进制内容填充整个区域
        font_example = tkFont.Font(size=12)

        self.hex_text.configure(font=font_example)
        scrollbar = ttkb.Scrollbar(self.details,bootstyle="info")
        scrollbar.pack(side=RIGHT, fill=Y)

        self.hex_text['yscrollcommand'] = scrollbar.set
        scrollbar['command'] = self.hex_text.yview



if __name__ == '__main__':
    root = tk.Tk()
    wirewolf = WirewolfUI(root)

    wirewolf.root.mainloop()