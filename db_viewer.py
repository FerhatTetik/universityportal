import sqlite3
from tabulate import tabulate

def view_table_data(table_name):
    # Veritabanı bağlantısı
    conn = sqlite3.connect('campus_portal.db')
    cursor = conn.cursor()
    
    # Tablo yapısını al
    cursor.execute(f"PRAGMA table_info({table_name})")
    columns = cursor.fetchall()
    column_names = [col[1] for col in columns]
    
    # Tablo verilerini al
    cursor.execute(f"SELECT * FROM {table_name}")
    rows = cursor.fetchall()
    
    # Verileri tablo formatında göster
    print(f"\n{table_name.upper()} TABLOSU:")
    print(tabulate(rows, headers=column_names, tablefmt="grid"))
    
    conn.close()

def main():
    # Tüm tabloları listele
    conn = sqlite3.connect('campus_portal.db')
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
    tables = cursor.fetchall()
    conn.close()
    
    print("Veritabanındaki Tablolar:")
    for i, table in enumerate(tables, 1):
        print(f"{i}. {table[0]}")
    
    while True:
        try:
            choice = input("\nGörüntülemek istediğiniz tablonun numarasını girin (Çıkmak için 'q'): ")
            if choice.lower() == 'q':
                break
            
            table_index = int(choice) - 1
            if 0 <= table_index < len(tables):
                view_table_data(tables[table_index][0])
            else:
                print("Geçersiz tablo numarası!")
        except ValueError:
            print("Lütfen geçerli bir numara girin!")
        except Exception as e:
            print(f"Hata oluştu: {e}")

if __name__ == "__main__":
    main() 