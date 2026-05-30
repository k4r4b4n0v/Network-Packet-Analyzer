#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Network Packet Analyzer
Открывает PCAP-файлы и показывает по каждому пакету:
- время, протокол (TCP/UDP), IP-адреса и порты источника/назначения,
- TLS/SSL-рекорды (тип, версия, длина),
- первые 50 байт полезной нагрузки в HEX и ASCII.
Поддерживает .pcap/.pcapng, drag & drop, тёмную тему, локализацию (рус/англ).
"""

import sys
import locale
from datetime import datetime

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QPlainTextEdit,
    QVBoxLayout, QWidget, QMenuBar, QMenu,
    QAction, QFileDialog, QMessageBox, QProgressBar,
    QStatusBar
)
from PyQt5.QtCore import QThread, pyqtSignal, Qt
from PyQt5.QtGui import QPalette, QColor, QDragEnterEvent, QDropEvent

from scapy.all import PcapReader, IP, TCP, UDP, Raw


# ============================================================
# Language resources
# ============================================================
STRINGS = {
    'en': {
        'window_title': "Network Packet Analyzer",
        'menu_file': "File",
        'menu_view': "View",
        'menu_help': "Help",                # теперь это будет QAction, а не QMenu
        'menu_language': "Language",
        'lang_english': "English",
        'lang_russian': "Russian",
        'action_open': "Open PCAP File",
        'action_save': "Save Results to TXT",
        'action_exit': "Exit",
        'action_about': "About",
        'action_dark_theme': "Dark Theme",
        'open_dialog_title': "Select PCAP File",
        'save_dialog_title': "Save Results",
        'save_dialog_filter': "Text files (*.txt);;All files (*)",
        'loading': "[*] Loading file: {}",
        'analysis_finished': "[*] Analysis finished. Processed {} packets.",
        'error': "[ERROR] {}",
        'separator': "=" * 70,
        'time_label': "[Time] {}",
        'protocol_label': "[Protocol] {}",
        'source_label': "[Source] {}:{}",
        'dest_label': "[Destination] {}:{}",
        'tls_label': "[TLS/SSL] Type: {}, Version: {}, Length: {} bytes",
        'payload_hex_label': "[Data HEX] {}",
        'payload_ascii_label': "[Data ASCII] {}",
        'payload_none': "[Data] None",
        'tls_types': {
            0x14: "Change Cipher Spec",
            0x15: "Alert",
            0x16: "Handshake",
            0x17: "Application Data"
        },
        'about_title': "About Network Packet Analyzer",
        'about_text': (
            "Network Packet Analyzer\n"
            "Version 2.0\n\n"
            "Description:\n"
            "  • View PCAP dump packets with details:\n"
            "    time, protocol, IP/ports, TLS/SSL, data (HEX + ASCII).\n"
            "  • Supports .pcap and .pcapng.\n"
            "  • Drag & Drop, dark theme, multilingual.\n\n"
            "Author: Karabanov A.R.\n"
            "Year: 2026"
        ),
        'status_ready': "Ready",
        'status_analyzing': "Analyzing: {}",
        'status_completed': "Analysis completed",
        'status_lang_changed': "Language changed to English",
        'status_saved': "Results saved to: {}",
        'warning_no_results': "No results to save. Please open and analyze a PCAP file first.",
        'warning_title': "Warning",
        'error_save': "Failed to save file:\n{}",
        'success_save': "Results successfully saved to:\n{}",
        'drag_drop_hint': "You can also drag & drop a PCAP file here.",
        'report_header': "Network Packet Analyzer — Analysis Report",
        'report_file': "File: {}",
        'report_date': "Date: {}",
    },
    'ru': {
        'window_title': "Анализатор сетевого трафика",
        'menu_file': "Файл",
        'menu_view': "Вид",
        'menu_help': "Справка",              # тоже QAction
        'menu_language': "Язык",
        'lang_english': "Английский",
        'lang_russian': "Русский",
        'action_open': "Открыть PCAP файл",
        'action_save': "Сохранить результаты в TXT",
        'action_exit': "Выход",
        'action_about': "О программе",
        'action_dark_theme': "Тёмная тема",
        'open_dialog_title': "Выберите PCAP файл",
        'save_dialog_title': "Сохранить результаты",
        'save_dialog_filter': "Текстовые файлы (*.txt);;Все файлы (*)",
        'loading': "[*] Загрузка файла: {}",
        'analysis_finished': "[*] Анализ завершён. Обработано пакетов: {}.",
        'error': "[ОШИБКА] {}",
        'separator': "=" * 70,
        'time_label': "[Время] {}",
        'protocol_label': "[Протокол] {}",
        'source_label': "[Источник] {}:{}",
        'dest_label': "[Назначение] {}:{}",
        'tls_label': "[TLS/SSL] Тип: {}, Версия: {}, Длина: {} байт",
        'payload_hex_label': "[Данные HEX] {}",
        'payload_ascii_label': "[Данные ASCII] {}",
        'payload_none': "[Данные] Отсутствуют",
        'tls_types': {
            0x14: "Смена шифра",
            0x15: "Предупреждение",
            0x16: "Рукопожатие",
            0x17: "Данные приложения"
        },
        'about_title': "О программе — Анализатор сетевого трафика",
        'about_text': (
            "Анализатор сетевого трафика\n"
            "Версия 2.0\n\n"
            "Описание:\n"
            "  • Просмотр пакетов из PCAP-дампов с детализацией:\n"
            "    время, протокол, IP/порты, TLS/SSL, данные (HEX + ASCII).\n"
            "  • Поддержка .pcap и .pcapng.\n"
            "  • Drag & Drop, тёмная тема, мультиязычность.\n\n"
            "Автор: Карабанов А.Р.\n"
            "Год: 2026"
        ),
        'status_ready': "Готов",
        'status_analyzing': "Анализ: {}",
        'status_completed': "Анализ завершён",
        'status_lang_changed': "Язык изменён на русский",
        'status_saved': "Результаты сохранены: {}",
        'warning_no_results': "Нет результатов для сохранения. Откройте и проанализируйте PCAP файл.",
        'warning_title': "Предупреждение",
        'error_save': "Не удалось сохранить файл:\n{}",
        'success_save': "Результаты успешно сохранены:\n{}",
        'drag_drop_hint': "Можно также перетащить PCAP-файл в это окно.",
        'report_header': "Анализатор сетевого трафика — Отчёт",
        'report_file': "Файл: {}",
        'report_date': "Дата: {}",
    }
}


# ============================================================
# Packet processing thread
# ============================================================
class PacketProcessingThread(QThread):
    """Thread for asynchronous packet processing using iterative reader."""
    
    packet_received = pyqtSignal(dict)
    progress_updated = pyqtSignal(int)
    finished = pyqtSignal()

    def __init__(self, pcap_file):
        super().__init__()
        self.pcap_file = pcap_file
        self.stop_flag = False

    def stop(self):
        self.stop_flag = True

    def run(self):
        count = 0
        try:
            with PcapReader(self.pcap_file) as reader:
                for pkt in reader:
                    if self.stop_flag:
                        break
                    info = self._extract_packet_info(pkt)
                    self.packet_received.emit(info)
                    count += 1
                    self.progress_updated.emit(count)
                    self.msleep(1)
        except Exception as e:
            self.packet_received.emit({'error': str(e)})
        finally:
            self.finished.emit()

    def _extract_packet_info(self, pkt):
        """Extract structured information from a single packet."""
        try:
            try:
                timestamp = float(pkt.time)
            except Exception:
                timestamp = 0.0

            info = {
                'time': datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3],
                'src_ip': None,
                'dst_ip': None,
                'src_port': None,
                'dst_port': None,
                'protocol': 'OTHER',
                'payload_hex': '',
                'payload_text': '',
                'tls_info': None
            }

            if IP not in pkt:
                return info

            info['src_ip'] = pkt[IP].src
            info['dst_ip'] = pkt[IP].dst

            if TCP in pkt:
                info['protocol'] = 'TCP'
                info['src_port'] = pkt[TCP].sport
                info['dst_port'] = pkt[TCP].dport
                self._detect_tls(pkt, info)
            elif UDP in pkt:
                info['protocol'] = 'UDP'
                info['src_port'] = pkt[UDP].sport
                info['dst_port'] = pkt[UDP].dport

            if Raw in pkt:
                raw_bytes = bytes(pkt[Raw].load)
                payload_data = raw_bytes[:50]
                info['payload_hex'] = ' '.join(f'{b:02X}' for b in payload_data)
                info['payload_text'] = ''.join(
                    chr(b) if 32 <= b < 127 else '.' for b in payload_data
                )

            return info
        except Exception as e:
            return {'error': f'Packet parse error: {str(e)}'}

    def _detect_tls(self, pkt, info):
        """Detect TLS/SSL records (works on any port)."""
        if Raw not in pkt:
            return
        try:
            payload = bytes(pkt[Raw].load)
            if len(payload) < 5:
                return
            content_type = payload[0]
            version_major = payload[1]
            version_minor = payload[2]
            length = (payload[3] << 8) | payload[4]
            if 0x14 <= content_type <= 0x17:
                info['tls_info'] = {
                    'type_code': content_type,
                    'version': f"{version_major}.{version_minor}",
                    'length': length
                }
        except Exception:
            pass


# ============================================================
# Main window
# ============================================================
class NetworkPacketAnalyzer(QMainWindow):
    """Main application window."""

    def __init__(self):
        super().__init__()
        sys_locale = locale.getdefaultlocale()[0]
        self.current_language = 'ru' if sys_locale and sys_locale.startswith('ru') else 'en'
        
        self.current_thread = None
        self.full_log = []
        self.current_file_path = None
        self.packet_count = 0
        self.dark_theme_enabled = False

        self._init_ui()
        self._apply_theme()

    def _init_ui(self):
        """Set up all UI elements."""
        self.setWindowTitle(STRINGS[self.current_language]['window_title'])
        self.setGeometry(100, 100, 1100, 750)
        self.setAcceptDrops(True)

        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)

        self.text_output = QPlainTextEdit()
        self.text_output.setReadOnly(True)
        self.text_output.setMaximumBlockCount(5000)
        self.text_output.setPlaceholderText(
            STRINGS[self.current_language]['drag_drop_hint']
        )
        layout.addWidget(self.text_output)

        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.progress_bar = QProgressBar()
        self.progress_bar.setMaximumWidth(200)
        self.progress_bar.setVisible(False)
        self.status_bar.addPermanentWidget(self.progress_bar)
        self.status_bar.showMessage(STRINGS[self.current_language]['status_ready'])

        self._create_menus()

    def _create_menus(self):
        """Create menu bar with a clickable Help/Справка action."""
        menubar = self.menuBar()

        # File menu
        self.file_menu = menubar.addMenu(STRINGS[self.current_language]['menu_file'])
        self._build_file_menu()

        # View menu
        self.view_menu = menubar.addMenu(STRINGS[self.current_language]['menu_view'])
        self.dark_theme_action = QAction(
            STRINGS[self.current_language]['action_dark_theme'], self, checkable=True
        )
        self.dark_theme_action.setChecked(False)
        self.dark_theme_action.toggled.connect(self._toggle_dark_theme)
        self.view_menu.addAction(self.dark_theme_action)

        # Language menu
        self.lang_menu = menubar.addMenu(STRINGS[self.current_language]['menu_language'])
        self._build_language_menu()

        # Help action (clickable, not a submenu)
        self.help_action = QAction(STRINGS[self.current_language]['menu_help'], self)
        self.help_action.triggered.connect(self._show_about)
        menubar.addAction(self.help_action)

    def _build_file_menu(self):
        """Recreate file menu actions."""
        self.file_menu.clear()
        strings = STRINGS[self.current_language]

        open_action = QAction(strings['action_open'], self)
        open_action.setShortcut("Ctrl+O")
        open_action.triggered.connect(self._open_pcap_file)
        self.file_menu.addAction(open_action)

        save_action = QAction(strings['action_save'], self)
        save_action.setShortcut("Ctrl+S")
        save_action.triggered.connect(self._save_results)
        self.file_menu.addAction(save_action)

        self.file_menu.addSeparator()

        exit_action = QAction(strings['action_exit'], self)
        exit_action.setShortcut("Ctrl+Q")
        exit_action.triggered.connect(self.close)
        self.file_menu.addAction(exit_action)

    def _build_language_menu(self):
        """Recreate language menu."""
        self.lang_menu.clear()
        strings = STRINGS[self.current_language]

        lang_en = QAction(strings['lang_english'], self)
        lang_en.triggered.connect(lambda: self._change_language('en'))
        self.lang_menu.addAction(lang_en)

        lang_ru = QAction(strings['lang_russian'], self)
        lang_ru.triggered.connect(lambda: self._change_language('ru'))
        self.lang_menu.addAction(lang_ru)

    def _change_language(self, lang):
        """Switch application language and update all UI strings."""
        if lang == self.current_language:
            return

        self.current_language = lang
        strings = STRINGS[lang]

        self.setWindowTitle(strings['window_title'])
        self.file_menu.setTitle(strings['menu_file'])
        self.view_menu.setTitle(strings['menu_view'])
        self.lang_menu.setTitle(strings['menu_language'])
        # Update the help action text
        self.help_action.setText(strings['menu_help'])
        self.dark_theme_action.setText(strings['action_dark_theme'])
        self.text_output.setPlaceholderText(strings['drag_drop_hint'])

        self._build_file_menu()
        self._build_language_menu()

        self.status_bar.showMessage(strings['status_lang_changed'])

    def _toggle_dark_theme(self, enabled):
        """Switch between light and dark color schemes."""
        self.dark_theme_enabled = enabled
        self._apply_theme()

    def _apply_theme(self):
        """Set the application palette based on dark_theme_enabled."""
        app = QApplication.instance()
        if self.dark_theme_enabled:
            dark_palette = QPalette()
            dark_palette.setColor(QPalette.Window, QColor(53, 53, 53))
            dark_palette.setColor(QPalette.WindowText, Qt.white)
            dark_palette.setColor(QPalette.Base, QColor(35, 35, 35))
            dark_palette.setColor(QPalette.AlternateBase, QColor(53, 53, 53))
            dark_palette.setColor(QPalette.ToolTipBase, Qt.white)
            dark_palette.setColor(QPalette.ToolTipText, Qt.white)
            dark_palette.setColor(QPalette.Text, Qt.white)
            dark_palette.setColor(QPalette.Button, QColor(53, 53, 53))
            dark_palette.setColor(QPalette.ButtonText, Qt.white)
            dark_palette.setColor(QPalette.BrightText, Qt.red)
            dark_palette.setColor(QPalette.Link, QColor(42, 130, 218))
            dark_palette.setColor(QPalette.Highlight, QColor(42, 130, 218))
            dark_palette.setColor(QPalette.HighlightedText, Qt.black)
            app.setPalette(dark_palette)
        else:
            app.setPalette(app.style().standardPalette())

    def dragEnterEvent(self, event: QDragEnterEvent):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event: QDropEvent):
        urls = event.mimeData().urls()
        if urls:
            file_path = urls[0].toLocalFile()
            if file_path.lower().endswith(('.pcap', '.pcapng')):
                self._start_analysis(file_path)

    def _open_pcap_file(self):
        """Open file dialog and start analysis."""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            STRINGS[self.current_language]['open_dialog_title'],
            "",
            "PCAP files (*.pcap *.pcapng);;All files (*)"
        )
        if file_path:
            self._start_analysis(file_path)

    def _start_analysis(self, file_path):
        """Stop previous thread and launch new analysis."""
        if self.current_thread and self.current_thread.isRunning():
            self.current_thread.stop()
            self.current_thread.wait(5000)

        self.current_file_path = file_path
        self.full_log.clear()
        self.text_output.clear()
        self.packet_count = 0

        strings = STRINGS[self.current_language]
        self._append_to_log(strings['loading'].format(file_path))
        self.status_bar.showMessage(strings['status_analyzing'].format(file_path))
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)

        self.current_thread = PacketProcessingThread(file_path)
        self.current_thread.packet_received.connect(self._on_packet_received)
        self.current_thread.progress_updated.connect(self._update_progress)
        self.current_thread.finished.connect(self._on_analysis_finished)
        self.current_thread.start()

    def _on_packet_received(self, info):
        """Process a packet info dict and display."""
        strings = STRINGS[self.current_language]

        if 'error' in info:
            error_msg = strings['error'].format(info['error'])
            self._append_to_log(error_msg)
            return

        lines = []
        lines.append(strings['separator'])
        lines.append(strings['time_label'].format(info['time']))
        lines.append(strings['protocol_label'].format(info['protocol']))

        if info['src_ip']:
            src = strings['source_label'].format(
                info['src_ip'], info['src_port'] if info['src_port'] else 'N/A')
            dst = strings['dest_label'].format(
                info['dst_ip'], info['dst_port'] if info['dst_port'] else 'N/A')
            lines.append(src)
            lines.append(dst)

        if info['tls_info']:
            tls_type_name = strings['tls_types'].get(
                info['tls_info']['type_code'],
                f"0x{info['tls_info']['type_code']:02X}"
            )
            tls_line = strings['tls_label'].format(
                tls_type_name,
                info['tls_info']['version'],
                info['tls_info']['length']
            )
            lines.append(tls_line)

        if info['payload_hex']:
            lines.append(strings['payload_hex_label'].format(info['payload_hex']))
            lines.append(strings['payload_ascii_label'].format(info['payload_text']))
        else:
            lines.append(strings['payload_none'])

        output = "\n".join(lines)
        self._append_to_log(output)

    def _append_to_log(self, text):
        """Add text to on-screen widget and full log storage."""
        self.text_output.appendPlainText(text)
        self.full_log.append(text)

    def _update_progress(self, count):
        """Update progress bar with packet count."""
        self.packet_count = count
        self.progress_bar.setValue(count % 100)
        self.progress_bar.setFormat(f"{count} packets")

    def _on_analysis_finished(self):
        """Cleanup after analysis thread finishes."""
        strings = STRINGS[self.current_language]
        finish_msg = strings['analysis_finished'].format(self.packet_count)
        self._append_to_log(finish_msg)
        self.status_bar.showMessage(strings['status_completed'])
        self.progress_bar.setVisible(False)

    def _save_results(self):
        """Save complete log to a text file."""
        strings = STRINGS[self.current_language]
        if not self.full_log:
            QMessageBox.warning(self, strings['warning_title'],
                                strings['warning_no_results'])
            return

        file_path, _ = QFileDialog.getSaveFileName(
            self,
            strings['save_dialog_title'],
            "analysis_results.txt",
            strings['save_dialog_filter']
        )
        if not file_path:
            return

        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(f"{strings['report_header']}\n")
                f.write(strings['report_file'].format(
                    self.current_file_path if self.current_file_path else 'Unknown') + "\n")
                f.write(strings['report_date'].format(
                    datetime.now().strftime('%Y-%m-%d %H:%M:%S')) + "\n")
                f.write(f"{'=' * 70}\n\n")
                f.write("\n".join(self.full_log))

            self.status_bar.showMessage(strings['status_saved'].format(file_path))
            QMessageBox.information(self, "OK", strings['success_save'].format(file_path))
        except Exception as e:
            QMessageBox.critical(self, "Error", strings['error_save'].format(str(e)))

    def _show_about(self):
        """Display About dialog."""
        strings = STRINGS[self.current_language]
        QMessageBox.about(self, strings['about_title'], strings['about_text'])

    def closeEvent(self, event):
        """Ensure clean thread termination on window close."""
        if self.current_thread and self.current_thread.isRunning():
            self.current_thread.stop()
            self.current_thread.wait(5000)
        event.accept()


# ============================================================
def main():
    app = QApplication(sys.argv)
    app.setApplicationName("Network Packet Analyzer")
    app.setOrganizationName("Karabanov")
    app.setStyle('Fusion')

    window = NetworkPacketAnalyzer()
    window.show()

    sys.exit(app.exec_())

if __name__ == "__main__":
    main()