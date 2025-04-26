# Audio Steganography - Dokumentace

## Obsah
1. [Úvod](#úvod)
2. [Instalace](#instalace)
3. [Spuštění programu](#spuštění-programu)
4. [Použití programu](#použití-programu)
   - [Vkládání tajné zprávy](#vkládání-tajné-zprávy)
   - [Extrakce tajné zprávy](#extrakce-tajné-zprávy)
   - [Výpočet kapacity a informace o využití](#výpočet-kapacity-a-informace-o-využití)
   - [Zobrazení detailů procesu](#zobrazení-detailů-procesu)
5. [Technické detaily](#technické-detaily)
   - [Princip fungování](#princip-fungování)
   - [Integrita dat](#integrita-dat)
   - [Bezpečnost](#bezpečnost)
6. [Externí knihovny](#externí-knihovny)
7. [Autoři](#autoři)

## Úvod

Audio Steganography je program pro skrývání a extrakci tajných zpráv v audio souborech formátu WAV. Program využívá metodu LSB (Least Significant Bit) k ukrytí dat a zajišťuje integritu zprávy pomocí hashovací funkce SHA-256. Pro dodatečnou bezpečnost je zpráva šifrována pomocí XOR šifrování.

![image](https://github.com/user-attachments/assets/80100712-cbcd-47af-a6ff-1a43e60ecc38)


## Instalace

### Požadavky
- Python 3.6 nebo novější
- Následující knihovny:
  - tkinter (součást standardní instalace Pythonu)
  - numpy (1.19.0 nebo novější)
  - wave (součást standardní instalace Pythonu)

### Instalace potřebných knihoven

```bash
pip install numpy==1.19.0
```

## Spuštění programu

Program lze spustit následujícím příkazem ve složce s programem:

```bash
python steg_gui.py
```

## Použití programu

## důležitá informace o programu
- Program má jeden malý problém a to, že se musí nejprve zadat parametry jako zpráva a heslo a následně až vložit audio soubor. Pokud je to provedeno opačně program má problém s detekcí audiosouboru. Proto VŽDY VLOŽÍT NEJRPVE TEXT A HESLO A NÁSLEDNĚ AUDIO SOUBOR.

Program má dvě hlavní funkce:
1. Vkládání tajné zprávy do WAV souboru
2. Extrakce tajné zprávy z WAV souboru

### Vkládání tajné zprávy

1. V sekci "Schovej Message" klikněte na tlačítko "Vyber WAV soubor, do kterého chceš zprávu vložit".
2. Po vybrání souboru se zobrazí informace o dostupné kapacitě souboru.
3. Zadejte tajnou zprávu do textového pole "Tajná zpráva".
4. Zadejte heslo, které bude potřeba pro pozdější extrakci zprávy.
5. Při zadávání textu se automaticky aktualizují informace o využité kapacitě.
6. Klikněte na tlačítko "Schovej zprávu".
7. Po úspěšném vložení zprávy se zobrazí potvrzení a SHA-256 hash výstupního souboru.

### Extrakce tajné zprávy

1. V sekci "Extrahuj Message" klikněte na tlačítko "Vyber wav soubor, ze kterého chceš tajnou zprávu vyextrahovat".
2. Po vybrání souboru se zobrazí SHA-256 hash vstupního souboru.
3. Zadejte heslo, které bylo použito při vkládání zprávy.
4. Klikněte na tlačítko "Extrahuj zprávu".
5. Extrahovaná zpráva se zobrazí v textovém poli "Extrahovaná zpráva".

### Výpočet kapacity a informace o využití

Program automaticky vypočítává a zobrazuje následující informace:
- Celková kapacita audio souboru (v bitech, bajtech a znacích)
- Využitá kapacita při zadání zprávy (v bitech, bajtech a znacích)
- Zbývající kapacita (v bitech, bajtech a znacích)
- Maximální délka zprávy, kterou lze do souboru vložit

Tyto informace se aktualizují v reálném čase při zadávání zprávy, hesla a samotného audio souboru.

### Zobrazení detailů procesu

Program nabízí možnost zobrazit detailní informace o procesu vkládání nebo extrakce:

1. Pro zobrazení detailů vkládání klikněte na tlačítko "Zobrazit detaily procesu schování zprávy".
2. Pro zobrazení detailů extrakce klikněte na tlačítko "Zobrazit detaily procesu extrakce zprávy".

Tyto detaily zahrnují:
- Původní zprávu a její binární reprezentaci
- SHA-256 hash zprávy
- Zašifrovaná data
- Finální payload vložený do audio souboru

## Technické detaily

### Princip fungování

Program využívá metodu LSB (Least Significant Bit) pro ukrytí dat v audio souboru. Tato metoda spočívá v modifikaci nejméně významných bitů audio vzorků, čímž je dosaženo minimálního vlivu na kvalitu zvuku.

Proces vkládání dat:
1. Zpráva je převedena na bajty pomocí UTF-8 kódování
2. Vytvoří se SHA-256 hash zprávy pro kontrolu integrity
3. Hash a zpráva jsou spojeny do jednoho bloku dat
4. Data jsou zašifrována pomocí XOR šifrování s klíčem odvozeným z hesla
5. Připraví se hlavička obsahující délku zašifrovaných dat (32 bitů)
6. Hlavička a zašifrovaná data jsou vloženy do LSB jednotlivých audio vzorků

Proces extrakce dat:
1. Extrahuje se hlavička pro zjištění délky zašifrovaných dat
2. Extrahují se zašifrovaná data z LSB audio vzorků
3. Data jsou dešifrována pomocí XOR šifrování s klíčem odvozeným z hesla
4. Extrahuje se hash a zpráva
5. Vypočítá se hash extrahované zprávy a porovná se s extrahovaným hashem pro kontrolu integrity
6. Zpráva je dekódována z bajtů na text pomocí UTF-8 kódování

### Integrita dat

Program zajišťuje integritu dat pomocí hashovací funkce SHA-256. Před vložením zprávy do audio souboru je vypočítán hash zprávy, který je uložen spolu se zprávou. Při extrakci je hash znovu vypočítán a porovnán s uloženým hashem. Pokud se hashe neshodují, program vyhodí chybu, což může indikovat poškození dat nebo použití nesprávného hesla.

### Bezpečnost

Bezpečnost programu je zajištěna kombinací steganografie a šifrování:
- Steganografie: Tajná zpráva je ukryta v LSB audio vzorků, což je pro běžné uživatele neviditelné.
- Šifrování: Zpráva a hash jsou šifrovány pomocí XOR šifrování s klíčem odvozeným z hesla.
- Integrita: SHA-256 hash zajišťuje integritu dat a detekci manipulace.

## Externí knihovny

Program využívá následující externí knihovny:

| Knihovna | Verze | Účel |
|----------|-------|------|
| tkinter | Součást Python | GUI (grafické uživatelské rozhraní) |
| numpy | 1.19.0 nebo novější | Manipulace s audio daty jako s poli |
| wave | Součást Python | Čtení a zápis WAV souborů |
| hashlib | Součást Python | Výpočet SHA-256 hashe |
| os | Součást Python | Operace se soubory a cestami |

## Autoři

Program vytvořili Nekuda a Kala jako součást projektu. 
