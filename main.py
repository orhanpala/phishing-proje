import streamlit as st
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.naive_bayes import MultinomialNB
import time
import os
import base64
from collections import Counter
import re

# ---------------------------------------------------------
# 1. SAYFA VE MODEL AYARLARI (EN ÜSTTE OLMALI)
# ---------------------------------------------------------
try:
    st.set_page_config(
        page_title="Munzur AI Güvenlik",
        page_icon="🛡️", # Hata riskine karşı emoji kullanıyoruz
        layout="wide",
        initial_sidebar_state="expanded"
    )
except:
    pass 

# Dosya yolları
DOSYA_YOLU = 'phishing.csv'
USER_DB_FILE = 'users.csv'

# --- YARDIMCI: GÜVENLİ SAYFA YENİLEME ---
def safe_rerun():
    time.sleep(0.1) 
    try:
        st.rerun()
    except AttributeError:
        st.experimental_rerun()

# --- YARDIMCI: RESMİ BASE64'E ÇEVİRME (Logoyu göstermek için) ---
def get_img_as_base64(file):
    with open(file, "rb") as f:
        data = f.read()
    return base64.b64encode(data).decode()

# Logo HTML Oluşturucu (Yan Menü ve Login İçin)
def get_logo_html(width=60, font_size_title=18, font_size_subtitle=12):
    logo_path = "munzur_logo.png"
    img_html = ""
    
    if os.path.exists(logo_path):
        img_b64 = get_img_as_base64(logo_path)
        img_html = f'<img src="data:image/png;base64,{img_b64}" width="{width}">'
    else:
        # Yedek (İnternet Linki)
        img_html = f'<img src="https://upload.wikimedia.org/wikipedia/tr/0/05/Munzur_%C3%9Cniversitesi_Logosu.png" width="{width}">'
        
    return f"""
    <div style="display: flex; align-items: center; gap: 15px; padding-bottom: 20px;">
        {img_html}
        <div style="line-height: 1.2;">
            <div style="color: #1E90FF; font-weight: bold; font-size: {font_size_title}px; white-space: nowrap;">MUNZUR Aİ</div>
            <div style="color: #FFFFFF; font-size: {font_size_subtitle}px; white-space: nowrap;">MAİL KORUMA</div>
        </div>
    </div>
    """

# --- KULLANICI YÖNETİMİ FONKSİYONLARI ---

def get_users_db():
    if not os.path.exists(USER_DB_FILE):
        df = pd.DataFrame(columns=['username', 'password'])
        df.to_csv(USER_DB_FILE, index=False)
        return df
    try:
        return pd.read_csv(USER_DB_FILE)
    except pd.errors.EmptyDataError:
        return pd.DataFrame(columns=['username', 'password'])

def add_user(username, password):
    df = get_users_db()
    if not df.empty and username in df['username'].astype(str).values:
        return False, "Bu kullanıcı adı zaten alınmış."
    
    new_user = pd.DataFrame({'username': [username], 'password': [password]})
    df = pd.concat([df, new_user], ignore_index=True)
    df.to_csv(USER_DB_FILE, index=False)
    return True, "Kayıt başarılı! Şimdi giriş yapabilirsiniz."

def check_login(username, password):
    df = get_users_db()
    if df.empty: return False
    df['username'] = df['username'].astype(str)
    df['password'] = df['password'].astype(str)
    user = df[(df['username'] == username) & (df['password'] == password)]
    return not user.empty

# --- VERİ SETİ VE MODEL FONKSİYONLARI ---

def istatistikleri_getir():
    try:
        try: df = pd.read_csv(DOSYA_YOLU, encoding='utf-8')
        except: df = pd.read_csv(DOSYA_YOLU, encoding='latin-1')
        
        if df.empty: return {"toplam": 0, "oltalama": 0, "guvenli": 0}
        
        oltalama = len(df[df['Kategori'].isin(['Oltalama', 'Phishing', 1, '1'])])
        guvenli = len(df[df['Kategori'].isin(['Güvenilir', 'Safe', 'Legitimate', 0, '0'])])
        return {"toplam": len(df), "oltalama": oltalama, "guvenli": guvenli}
    except:
        return {"toplam": 0, "oltalama": 0, "guvenli": 0}

def en_cok_gecen_kelimeler(limit=5):
    """Oltalama maillerinde en çok geçen kelimeleri bulur."""
    try:
        try: df = pd.read_csv(DOSYA_YOLU, encoding='utf-8')
        except: df = pd.read_csv(DOSYA_YOLU, encoding='latin-1')
        
        # Sadece oltalama maillerini al
        mapping = {'Oltalama': 1, 'Phishing': 1, '1': 1, 1: 1}
        df['label_temp'] = df['Kategori'].map(mapping)
        phish_df = df[df['label_temp'] == 1]
        
        if phish_df.empty:
            return []

        text = " ".join(phish_df['İçerik'].astype(str).tolist()).lower()
        # Basit temizlik
        words = re.findall(r'\w+', text)
        # Önemsiz kelimeleri filtrele (stopwords benzeri basit filtre)
        onemsizler = {'ve', 'bir', 'bu', 'da', 'de', 'ile', 'için', 'the', 'to', 'of', 'and', 'in', 'a', 'is'}
        words = [w for w in words if w not in onemsizler and len(w) > 3]
        
        counter = Counter(words)
        return counter.most_common(limit)
    except Exception as e:
        return []

def veritabanina_ekle(metin, etiket):
    try:
        try: df = pd.read_csv(DOSYA_YOLU, encoding='utf-8')
        except: df = pd.read_csv(DOSYA_YOLU, encoding='latin-1')
        
        yeni_id = 1
        if 'ID' in df.columns and not df.empty:
            yeni_id = df['ID'].max() + 1

        tekrar = 100
        yeni_veri = {
            'ID': range(yeni_id, yeni_id + tekrar),
            'Konu': ['Geri Bildirim'] * tekrar,
            'Gönderen': ['Manuel'] * tekrar,
            'İçerik': [metin] * tekrar,
            'Kategori': [etiket] * tekrar
        }
        
        df_yeni = pd.concat([df, pd.DataFrame(yeni_veri)], ignore_index=True)
        df_yeni.to_csv(DOSYA_YOLU, index=False, encoding='utf-8')
        return True, len(df_yeni)
    except Exception as e:
        st.error(f"Kayıt hatası: {e}")
        return False, 0

@st.cache_resource
def modeli_egit():
    try:
        try: df = pd.read_csv(DOSYA_YOLU, encoding='utf-8')
        except: df = pd.read_csv(DOSYA_YOLU, encoding='latin-1')
        
        if df.empty: return None, None
        
        if 'İçerik' in df.columns and 'Kategori' in df.columns:
            df = df[['İçerik', 'Kategori']]
            df.columns = ['text', 'label']
        else:
            df = df.iloc[:, [3, 4]]
            df.columns = ['text', 'label']
            
        df = df.dropna()
        mapping = {'Oltalama': 1, 'Güvenilir': 0, 'Phishing': 1, 'Safe': 0, '1': 1, '0': 0, 1: 1, 0: 0}
        df['label'] = df['label'].map(mapping)
        df = df.dropna()
        df['text'] = df['text'].astype(str)
        
        vectorizer = CountVectorizer()
        X_vec = vectorizer.fit_transform(df['text'])
        model = MultinomialNB()
        model.fit(X_vec, df['label'])
        return model, vectorizer
    except Exception as e:
        st.error(f"Model hatası: {e}")
        return None, None

model, vectorizer = modeli_egit()

# ---------------------------------------------------------
# 3. UYGULAMA AKIŞI
# ---------------------------------------------------------

if 'logged_in' not in st.session_state: st.session_state.logged_in = False
if 'username' not in st.session_state: st.session_state.username = ''
if 'active_page' not in st.session_state: st.session_state.active_page = 'Ana Sayfa'

# --- LOGIN EKRANI ---
if not st.session_state.logged_in:
    col1, col2, col3 = st.columns([1, 6, 1])
    with col2:
        # LOGO VE YAZI (Login için büyük boy)
        st.markdown(get_logo_html(width=100, font_size_title=42, font_size_subtitle=24), unsafe_allow_html=True)
        
        st.markdown("<h3 style='text-align: center; margin-top: 20px;'>Giriş Paneli</h3>", unsafe_allow_html=True)
        
        tab1, tab2 = st.tabs(["Giriş Yap", "Kayıt Ol"])
        with tab1:
            kullanici = st.text_input("Kullanıcı Adı", key="l_u")
            sifre = st.text_input("Şifre", type="password", key="l_p")
            if st.button("Giriş Yap", type="primary", use_container_width=True):
                if check_login(kullanici, sifre):
                    st.session_state.logged_in = True
                    st.session_state.username = kullanici
                    st.success("Giriş Başarılı!")
                    safe_rerun()
                else: st.error("Hatalı bilgi.")
            
            # --- SOSYAL MEDYA GİRİŞLERİ ---
            st.markdown("<div style='text-align: center; margin-top: 15px; margin-bottom: 10px; color: #888;'>veya</div>", unsafe_allow_html=True)
            
            if st.button("🇬 Google ile Giriş Yap", use_container_width=True):
                st.warning("🚧 Bu özellik henüz yapım aşamasında.")
                
            if st.button("🍎 Apple ile Giriş Yap", use_container_width=True):
                st.warning("🚧 Bu özellik henüz yapım aşamasında.")
                
            if st.button("📘 Facebook ile Giriş Yap", use_container_width=True):
                st.warning("🚧 Bu özellik henüz yapım aşamasında.")

        with tab2:
            y_k = st.text_input("Yeni Kullanıcı Adı", key="r_u")
            y_s = st.text_input("Yeni Şifre", type="password", key="r_p")
            if st.button("Kayıt Ol", use_container_width=True):
                if len(y_k)>2 and len(y_s)>2:
                    ok, msg = add_user(y_k, y_s)
                    if ok: st.success(msg)
                    else: st.error(msg)
                else: st.warning("Bilgiler çok kısa.")

else:
    # --- ANA UYGULAMA (YAN MENÜ) ---
    with st.sidebar:
        # LOGO VE YAZI (Yan menü için normal boy)
        st.markdown(get_logo_html(width=60, font_size_title=18, font_size_subtitle=12), unsafe_allow_html=True)
        
        st.info(f"👤 **{st.session_state.username}**")
        if st.button("Çıkış Yap", use_container_width=True):
            st.session_state.logged_in = False
            safe_rerun()
        
        st.markdown("---")
        
        # --- İSTATİSTİK GÖSTERİMİ (CSS Hover Efekti ile) ---
        stats = istatistikleri_getir()
        
        # HTML ve CSS ile Hover Efekti
        hover_stats_html = f"""
        <style>
            .stat-container {{
                background-color: #262730;
                padding: 10px;
                border-radius: 5px;
                text-align: center;
                cursor: pointer;
                transition: background-color 0.3s ease;
                border: 1px solid #464b5c;
            }}
            .stat-container:hover {{
                background-color: #1E1E1E;
            }}
            .stat-default {{
                display: block;
                font-weight: bold;
                color: #FFFFFF;
                font-size: 14px;
            }}
            .stat-hover {{
                display: none;
                font-size: 13px;
                color: #e0e0e0;
            }}
            /* Hover Tetikleyicisi: Mouse üstüne gelince default gizle, hover'ı göster */
            .stat-container:hover .stat-default {{
                display: none;
            }}
            .stat-container:hover .stat-hover {{
                display: block;
            }}
        </style>
        
        <div class="stat-container">
            <div class="stat-default">
                📊 Veri Tabanı: {stats['toplam']} Kayıt
            </div>
            <div class="stat-hover">
                🔴 Oltalama: {stats['oltalama']} <br>
                🟢 Güvenli: {stats['guvenli']}
            </div>
        </div>
        """
        st.markdown(hover_stats_html, unsafe_allow_html=True)
        
        st.markdown("---")
        
        if st.button("🏠 Ana Sayfa", use_container_width=True, type="primary" if st.session_state.active_page == 'Ana Sayfa' else "secondary"):
            st.session_state.active_page = 'Ana Sayfa'
            safe_rerun()
        if st.button("📊 Veri Seti", use_container_width=True, type="primary" if st.session_state.active_page == 'Veri Seti Bilgisi' else "secondary"):
             st.session_state.active_page = 'Veri Seti Bilgisi'
             safe_rerun()
        if st.button("📬 Simülasyon", use_container_width=True, type="primary" if st.session_state.active_page == 'Simülasyon' else "secondary"):
            st.session_state.active_page = 'Simülasyon'
            safe_rerun()
        if st.button("🕵️ Manuel Analiz", use_container_width=True, type="primary" if st.session_state.active_page == 'Manuel' else "secondary"):
            st.session_state.active_page = 'Manuel'
            safe_rerun()
        if st.button("📧 Gmail Bağla", use_container_width=True, type="primary" if st.session_state.active_page == 'Gmail' else "secondary"):
            st.session_state.active_page = 'Gmail'
            safe_rerun()
            
        st.markdown("---")
        st.caption("Geliştirici: Orhan Pala")

    # --- SAYFA İÇERİKLERİ ---
    if st.session_state.active_page == 'Ana Sayfa':
        st.title("🛡️ Munzur AI Güvenlik Kalkanı")
        st.success(f"Hoş geldin {st.session_state.username}! Güvenlik taramasına başlamak için sol menüyü kullanabilirsin.")
        
        # --- ANA SAYFA KARTLARI (3'e Bölündü) ---
        c1, c2, c3 = st.columns(3)
        with c1:
            st.info("### 📬 Simülasyon")
            st.write("Hazır senaryoları test et.")
            if st.button("Git: Simülasyon"):
                st.session_state.active_page = 'Simülasyon'
                safe_rerun()
        with c2:
            st.warning("### 🕵️ Manuel Analiz")
            st.write("Metin yapıştır ve tarat.")
            if st.button("Git: Analiz"):
                st.session_state.active_page = 'Manuel'
                safe_rerun()
        with c3:
            st.error("### 📊 Veri Analizi")
            st.write("Veri setini ve durumu incele.")
            if st.button("Git: İstatistikler"):
                st.session_state.active_page = 'Veri Seti Bilgisi'
                safe_rerun()

    # --- YENİ EKLENEN SAYFA: VERİ SETİ BİLGİSİ ---
    elif st.session_state.active_page == 'Veri Seti Bilgisi':
        st.title("📊 Veri Seti Analizi ve İstatistikler")
        st.write("Munzur AI modelinin arkasındaki veri gücünü burada inceleyebilirsiniz.")
        
        # Üst Kısım: Sayaçlar
        stats = istatistikleri_getir()
        m1, m2, m3 = st.columns(3)
        m1.metric("Toplam Veri", f"{stats['toplam']}", delta="Kayıt")
        m2.metric("Oltalama Sayısı", f"{stats['oltalama']}", delta_color="inverse")
        m3.metric("Güvenli Sayısı", f"{stats['guvenli']}", delta_color="normal")
        
        st.divider()
        
        col_sol, col_sag = st.columns([1, 1])
        
        with col_sol:
            st.subheader("🚨 En Sık Geçen 'Oltalama' Kelimeleri")
            st.info("Bu kelimeler, oltalama saldırılarında en çok tespit edilen anahtar kelimelerdir.")
            
            top_words = en_cok_gecen_kelimeler(limit=8)
            if top_words:
                # Güzel bir görselleştirme için Pandas DataFrame bar chart kullanımı
                df_words = pd.DataFrame(top_words, columns=['Kelime', 'Frekans'])
                st.bar_chart(df_words.set_index('Kelime'))
                
                # Liste olarak da gösterelim
                txt = ""
                for k, v in top_words:
                    txt += f"- **{k}**: {v} kez\n"
                st.markdown(txt)
            else:
                st.warning("Veri seti henüz boş veya analiz edilecek veri yok.")

        with col_sag:
            st.subheader("📁 Veri Seti Hakkında")
            st.write("""
            Bu proje, **Munzur Üniversitesi** Siber Güvenlik çalışmaları kapsamında eğitilmiştir.
            Model, binlerce gerçek e-posta örneği üzerinden öğrenerek kendini geliştirir.
            """)
            st.markdown("""
            **Veri Seti Özellikleri:**
            * **ID:** Benzersiz kayıt numarası.
            * **İçerik:** E-posta metni.
            * **Kategori:** 'Oltalama' veya 'Güvenilir' etiketi.
            * **Kaynak:** Açık kaynaklı siber güvenlik veri setleri ve kullanıcı geri bildirimleri.
            """)
            
            # Veri setinden örnek birkaç satır gösterme
            try:
                try: df_preview = pd.read_csv(DOSYA_YOLU, encoding='utf-8')
                except: df_preview = pd.read_csv(DOSYA_YOLU, encoding='latin-1')
                if not df_preview.empty:
                    st.write("**Veri Setinden Örnekler (Son 5 Kayıt):**")
                    st.dataframe(df_preview[['İçerik', 'Kategori']].tail(5), use_container_width=True)
            except:
                st.write("Veri önizlemesi yüklenemedi.")

    elif st.session_state.active_page == 'Simülasyon':
        st.title("📬 Simüle Edilmiş Gelen Kutusu")
        mailler = [
            {"id": 1, "konu": "Tebrikler! iPhone Kazandınız", "metin": "Tebrikler! iPhone 15 kazandınız. Hemen tıklayın: http://odul.com"},
            {"id": 2, "konu": "Yemeksepeti Sipariş Onayı", "metin": "Siparişiniz alındı. Restoran siparişinizi onayladı. Afiyet olsun!"},
            {"id": 3, "konu": "Netflix Ödeme Sorunu", "metin": "Sayın müşteri, ödemeniz alınamadı. Hesabınız kapatılacak. Güncellemek için tıklayın."}
        ]
        for mail in mailler:
            with st.expander(f"📩 {mail['konu']}"):
                st.write(mail['metin'])
                if st.button(f"Analiz Et", key=f"btn_{mail['id']}"):
                    st.session_state.analiz_metni = mail['metin']
                    st.session_state.analiz_yapildi = True
                    safe_rerun()
        
        if 'analiz_yapildi' in st.session_state and st.session_state.analiz_yapildi:
            st.markdown("---")
            metin = st.session_state.analiz_metni
            if model:
                vec = vectorizer.transform([metin])
                tahmin = model.predict(vec)[0]
                olasilik = np.max(model.predict_proba(vec)) * 100
                
                if tahmin == 1:
                    st.error(f"🚨 OLTALAMA! (Güven: %{olasilik:.1f})")
                    if st.button("✅ Düzelt: Güvenli", key="sim_fix_safe"):
                        veritabanina_ekle(metin, "Güvenilir")
                        st.cache_resource.clear()
                        st.success("Öğretildi!")
                        time.sleep(1)
                        del st.session_state.analiz_yapildi
                        safe_rerun()
                else:
                    st.success(f"✅ GÜVENLİ (Güven: %{olasilik:.1f})")
                    if st.button("🚨 Düzelt: Oltalama", key="sim_fix_phish"):
                        veritabanina_ekle(metin, "Oltalama")
                        st.cache_resource.clear()
                        st.success("Öğretildi!")
                        time.sleep(1)
                        del st.session_state.analiz_yapildi
                        safe_rerun()

    elif st.session_state.active_page == 'Manuel':
        st.title("🕵️ Manuel Analiz")
        user_input = st.text_area("Metni buraya yapıştırın:", height=150)
        if st.button("Taramayı Başlat"):
            if len(user_input) < 10: st.warning("Metin çok kısa.")
            else:
                st.session_state.analiz_metni = user_input
                st.session_state.analiz_yapildi_man = True
                safe_rerun()
        
        if 'analiz_yapildi_man' in st.session_state and st.session_state.analiz_yapildi_man:
            if model:
                vec = vectorizer.transform([st.session_state.analiz_metni])
                tahmin = model.predict(vec)[0]
                olasilik = np.max(model.predict_proba(vec)) * 100
                
                if tahmin == 1:
                    st.error(f"🚨 OLTALAMA! (%{olasilik:.1f})")
                    if st.button("✅ Düzelt: Güvenli", key="man_fix_safe"):
                        veritabanina_ekle(st.session_state.analiz_metni, "Güvenilir")
                        st.cache_resource.clear()
                        st.success("Öğretildi!")
                        del st.session_state.analiz_yapildi_man
                        safe_rerun()
                else:
                    st.success(f"✅ GÜVENLİ (%{olasilik:.1f})")
                    if st.button("🚨 Düzelt: Oltalama", key="man_fix_phish"):
                        veritabanina_ekle(st.session_state.analiz_metni, "Oltalama")
                        st.cache_resource.clear()
                        st.success("Öğretildi!")
                        del st.session_state.analiz_yapildi_man
                        safe_rerun()

    elif st.session_state.active_page == 'Gmail':
        st.title("📧 Gmail Bağla")
        st.info("🚧 Bu modül geliştirme aşamasındadır.")
        st.write("Yakında eklenecek özellikler: OAuth Girişi, Otomatik Tarama.")

        st.progress(65)


