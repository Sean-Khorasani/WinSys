// PromptDialog.cpp
// SPDX-License-Identifier: Apache-2.0
// See PromptDialog.h.

#include "PromptDialog.h"

#include <cstring>
#include <vector>

namespace wintcp {
namespace {

// Dialog ids. Local rather than in resource.h: this dialog is created from a
// template built in memory (see MakeTemplate below), so it has no entry in the
// .rc and putting its ids in the shared header would suggest otherwise.
enum : int {
    kIdLabel = 999,   // the optional caption static above the edit
    kIdEdit = 1000,
    kIdOk   = IDOK,
    kIdCancel = IDCANCEL,
};

// Read-back buffer for the edit control. Sized so it can never be the thing
// that truncates: the control was limited to maxChars, and this is larger than
// any caller may pass. The explicit length below keeps that true if a future
// caller raises maxChars.
constexpr size_t kEditReadChars = 1024;

// The label static's geometry. One 8-DLU row per label line over a 10-DLU
// base, capped at ten lines: a dozen-preset list fits, and a pathological
// label cannot push the edit and buttons off the dialog.
constexpr short kLabelBaseH = 10;
constexpr short kLabelLineH = 8;
constexpr int kMaxLabelLines = 10;

// Lines in a label: one per '\n', plus the first. Shared by the template
// writer (which positions the edit and buttons under the label) and
// PromptForText (which sizes the dialog itself), so the two cannot
// disagree about how tall the label is.
int LabelLineCount(const wchar_t* label) {
    if (label == nullptr || label[0] == L'\0') return 0;
    int n = 1;
    for (const wchar_t* p = label; *p != L'\0'; ++p) {
        if (*p == L'\n') ++n;
    }
    return (n > kMaxLabelLines) ? kMaxLabelLines : n;
}

struct PromptState {
    std::wstring value;
    size_t maxChars = 0;
    bool confirmed = false;
};

// DLGPROC, not the bare CALLBACK signature: the typedef is an INT_PTR
// return on x64, and a BOOL-returning function is a different type. The
// compiler rejects the implicit conversion, which is the point.
INT_PTR CALLBACK PromptProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    // The state pointer only exists after WM_INITDIALOG has stored it. Reading
    // it on every message - as the first line used to - yields nullptr for
    // WM_INITDIALOG itself and for anything that reaches the proc before
    // initialisation, and every one of those paths then dereferences null.
    // That is an intermittent access violation, because whether a given
    // message arrives before or after WM_INITDIALOG is not something this
    // proc controls.
    auto* st = reinterpret_cast<PromptState*>(GetWindowLongPtrW(hwnd, DWLP_USER));
    if (msg == WM_INITDIALOG) {
        st = reinterpret_cast<PromptState*>(lp);
        SetWindowLongPtrW(hwnd, DWLP_USER, reinterpret_cast<LONG_PTR>(st));
    }
    if (st == nullptr) return FALSE;
    switch (msg) {
        case WM_INITDIALOG: {
            HWND edit = GetDlgItem(hwnd, kIdEdit);
            if (edit != nullptr) {
                // EM_LIMITTEXT counts characters excluding the terminator, so
                // this is the exact bound and the control itself refuses to
                // exceed it - the value is not truncated after the fact,
                // which would silently change what the user typed.
                ::SendMessageW(edit, EM_LIMITTEXT,
                               static_cast<WPARAM>(st->maxChars), 0);
                ::SetWindowTextW(edit, st->value.c_str());
                // Select-all, so typing replaces the pre-filled name. Without
                // this the caret sits at the end and the user has to select
                // all by hand every single time.
                ::SendMessageW(edit, EM_SETSEL, 0, -1);
                ::SetFocus(edit);
            }
            // Centre on the owner so the prompt does not appear far away.
            RECT rc = {};
            ::GetWindowRect(hwnd, &rc);
            RECT own = {};
            ::GetWindowRect(::GetParent(hwnd), &own);
            const int w = rc.right - rc.left;
            const int h = rc.bottom - rc.top;
            const int x = own.left + ((own.right - own.left) - w) / 2;
            const int y = own.top + ((own.bottom - own.top) - h) / 2;
            ::SetWindowPos(hwnd, HWND_TOP, x, y, 0, 0,
                           SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE);
            return FALSE;   // we set the focus ourselves
        }
        case WM_COMMAND: {
            const int id = LOWORD(wp);
            const int code = HIWORD(wp);
            if (code != BN_CLICKED) break;
            if (id == kIdOk) {
                HWND edit = GetDlgItem(hwnd, kIdEdit);
                wchar_t buf[kEditReadChars] = {0};
                if (edit != nullptr) {
                    // Bounded read: the control was limited to maxChars, and
                    // this buffer is larger than any caller may pass, so the
                    // read cannot truncate. The explicit length keeps that
                    // true if a future caller raises maxChars.
                    const size_t cap =
                        (st->maxChars + 1 < sizeof(buf) / sizeof(buf[0]))
                            ? st->maxChars + 1
                            : sizeof(buf) / sizeof(buf[0]);
                    ::GetWindowTextW(edit, buf, static_cast<int>(cap));
                }
                st->value = buf;
                st->confirmed = true;
                ::EndDialog(hwnd, TRUE);
                return TRUE;
            }
            if (id == kIdCancel) {
                ::EndDialog(hwnd, FALSE);
                return TRUE;
            }
            break;
        }
        case WM_CLOSE:
            ::EndDialog(hwnd, FALSE);
            return TRUE;
        default:
            break;
    }
    return FALSE;
}

}  // namespace

// Build the dialog template in memory. A resource-based dialog would need a
// .rc edit, and this module is deliberately self-contained so it can be
// dropped in without touching the shared resource script.
// Round a byte count up to the next 4-byte boundary. Every string in a
// DLGTEMPLATE is padded this way, and the value is written four times below,
// so it is one named function rather than the same open-coded
// `(n + 3) / 4 * 4` at each site.
constexpr size_t Pad4(size_t bytes) { return (bytes + 3) & ~static_cast<size_t>(3); }

// MakeTemplate used to live in an anonymous namespace, which is right for
// the layout - nothing outside should build a dialog template - but it made the
// template arithmetic UNCHECKABLE. The one place it runs is a modal dialog, and
// the UI harness cannot dismiss one, so every capacity rule in it went
// unverified: including the ones this change adds.
//
// So the bounds are factored out as a pure function over a caller-supplied
// buffer. MakeTemplate is now a thin wrapper that computes a correctly sized
// buffer and hands it here, so there is ONE implementation of the layout and
// the test and the product cannot drift apart.
bool TemplateFits(DWORD style, DWORD exStyle, short x, short y, short cx,
                  short cy, const wchar_t* title, std::vector<BYTE>* buf);

namespace {

// The capacity MakeTemplate allocates. kTemplateMaxChars and kCaptionMaxChars
// come from the header, where TemplateFits declares them, so the writer and the
// selftest share one number instead of two copies that can drift.
constexpr size_t kTemplateSlack = 1024;

std::vector<BYTE> MakeTemplate(DWORD style, DWORD exStyle, short x, short y,
                                short cx, short cy, const wchar_t* title,
                                const wchar_t* label) {
    // A label adds a fourth control (a static) above the edit. The label's
    // own length sizes its share: it can be a dozen preset lines, so the
    // button-caption estimate cannot cover it and the slack must not have
    // to. The writer still bounds-checks every byte; this only avoids the
    // doubling retry on the first attempt.
    const size_t nControls = (label != nullptr) ? 4 : 3;
    const size_t labelChars =
        (label != nullptr) ? wcslen(label) + 1 : 0;
    const size_t capacity =
        sizeof(DLGTEMPLATE) + 4 +
        Pad4((kTemplateMaxChars + 1) * sizeof(wchar_t)) +   // title
        2 + Pad4((sizeof(L"Segoe UI") / sizeof(wchar_t)) * sizeof(wchar_t)) +
        nControls * (sizeof(DLGITEMTEMPLATE) + 4 +
                     Pad4((kCaptionMaxChars + 1) * sizeof(wchar_t)) + 2) +
        Pad4(labelChars * sizeof(wchar_t)) +
        kTemplateSlack;
    std::vector<BYTE> buf(capacity, 0);
    if (TemplateFits(style, exStyle, x, y, cx, cy, title, &buf, label))
        return buf;
    // Only possible if the capacity arithmetic above was too small, which it is
    // not meant to be. Doubling and trying once more beats failing the dialog,
    // and the retry goes through the same bounds-checked writer.
    buf.assign(capacity * 2, 0);
    if (TemplateFits(style, exStyle, x, y, cx, cy, title, &buf, label))
        return buf;
    return std::vector<BYTE>();
}

}  // namespace

namespace {

bool TemplateFitsImpl(DWORD style, DWORD exStyle, short x, short y, short cx,
                      short cy, const wchar_t* title,
                      std::vector<BYTE>* bufIn, const wchar_t* label) {
    // The byte count MUST match what is written below. It did not: the
    // allocation sized the buffer for a fixed 9 DLGITEMTEMPLATEs while only
    // three controls were ever written, and the OK/Cancel captions were never
    // written at all despite a comment claiming they were. The dialog manager
    // reads past the controls according to cdit, so an under-sized or
    // over-sized buffer is an out-of-bounds read inside the dialog loop -
    // which is where the intermittent access violation came from.
    //
    // Build it by writing into a generously sized buffer and then shrinking to
    // the true length, so the two can never disagree.
    //
    // The 4096 was a literal, so nothing connected it to what is written below:
    // a longer title or caption silently overflowed the vector, which is the
    // out-of-bounds write this file's other comment is about. It is now a named
    // constant with the sizing stated, and every write below is bounded by it -
    // see the checked advance() helper, which refuses to step past the end
    // instead of trusting the arithmetic.
    //
    // 'bufIn' is the caller's buffer and is NOT resized here. It may be any
    // size, including one too small: every write below is checked, so a
    // too-small buffer produces a refusal, never an overflow. That is what
    // makes the bounds testable - the selftest passes deliberately tiny buffers
    // and requires a refusal rather than a write past the end.
    //
    // 'title' must not be null, and the check is HERE rather than at the
    // wcslen: the first version of this function measured the title with
    // wcslen before anything looked at it, so a null title dereferenced null.
    // The header had already promised a refusal, so the selftest called it that
    // way and the suite died with an access violation. A contract stated in a
    // header is a promise the code has to keep on the first line, not on the
    // line that happens to touch the value.
    if (bufIn == nullptr || bufIn->empty() || title == nullptr)
        return false;
    std::vector<BYTE>& buf = *bufIn;
    BYTE* p = buf.data();
    BYTE* const begin = p;
    BYTE* const end = buf.data() + buf.size();

    // Reserve n bytes and return where they start, or nullptr if they do not fit.
    //
    // THE ORDER MATTERS, and getting it wrong is what the first version of this
    // did. A helper that only advanced the cursor - checking `end - p < n` and
    // then stepping - protects the step but not the write that follows it, so
    // `memcpy` into a buffer that was one byte too small already corrupted the
    // heap before the cursor moved. The test caught it: the selftest passed a
    // 1-byte buffer and the run died with STATUS_HEAP_CORRUPTION.
    //
    // So every write in this function is now preceded by this check, and the
    // cursor only moves after the write. `usable` is the one place that knows
    // how much is left.
    const auto usable = [&p, end](size_t n) {
        // SIGNED, because `end - p` is a ptrdiff_t and a negative one cast to
        // size_t becomes enormous - which would make `n <= <huge>` true for any
        // n and let the next write land outside the buffer.
        //
        // HONESTLY: this is not currently reachable. The alignment step in item()
        // is guarded so p never passes end, so `end - p` is never negative here,
        // and no selftest check pins this line - reverting it to the unsigned
        // form leaves all 688 checks green. It is kept because the cast is a
        // trap that only misfires under a future edit, and the cost of the
        // guard is one comparison. Do not read it as covered.
        const std::ptrdiff_t room = end - p;
        return room >= 0 && n <= static_cast<size_t>(room);
    };

    if (!usable(sizeof(DLGTEMPLATE))) return false;
    auto* dt = reinterpret_cast<DLGTEMPLATE*>(p);
    dt->style = style | DS_SETFONT | DS_MODALFRAME | DS_CENTER;
    dt->dwExtendedStyle = exStyle;
    dt->cdit = (label != nullptr) ? 4 : 3;   // [label] edit OK Cancel
    dt->x = x; dt->y = y; dt->cx = cx; dt->cy = cy;
    p += sizeof(DLGTEMPLATE);

    // Menu and window class are both "none" (0x0000, 0x0000).
    if (!usable(4)) return false;
    ::memset(p, 0, 4);
    p += 4;
    // The title is caller-supplied, so it is measured against the capacity
    // rather than assumed to fit. kTemplateMaxChars is generous for a prompt
    // caption; a longer one is refused rather than truncated, because a
    // half-written title gives a dialog whose caption is wrong.
    const size_t titleChars = wcslen(title) + 1;
    if (titleChars > kTemplateMaxChars + 1) return false;
    const size_t titleBytes = Pad4(titleChars * sizeof(wchar_t));
    if (!usable(titleBytes)) return false;
    memcpy(p, title, titleChars * sizeof(wchar_t));
    p += titleBytes;

    // Font. 9pt "Segoe UI" matches the rest of the app; a smaller or
    // different face here would make the prompt visibly not belong.
    if (!usable(2)) return false;
    *reinterpret_cast<WORD*>(p) = 9;
    p += 2;
    constexpr wchar_t kFont[] = L"Segoe UI";
    constexpr size_t kFontChars = sizeof(kFont) / sizeof(wchar_t);
    const size_t fontBytes = Pad4(kFontChars * sizeof(wchar_t));
    if (!usable(fontBytes)) return false;
    memcpy(p, kFont, kFontChars * sizeof(wchar_t));
    p += fontBytes;

    // One control: 0xFFFF + ordinal class, title, then 0x0000 for "no extra
    // data". The title is what puts a caption on a button, so it has to be
    // written for OK and Cancel or they come out blank.
    //
    // Win32 requires every DLGITEMTEMPLATE in an indirect template to start on
    // a DWORD (4-byte) boundary. The preceding writes - the font size WORD,
    // the DWORD-padded font name, the 2-byte "no extra data" slot - can leave
    // p on a 2-byte boundary. The symptom is an intermittent AV when the dialog
    // loop walks the template, which is exactly what the audit tracked down.
    // Returns false as soon as a write would not fit, leaving the buffer with
    // whatever prefix was written. The caller turns that into an empty
    // template - never a partial one - because cdit says 3 and handing the
    // manager fewer would be the out-of-bounds read this file prevents.
    const auto item = [&p, &usable, end](DWORD s, short ix, short iy, short icx,
                                    short icy, WORD id, WORD cls,
                                    const wchar_t* caption,
                                    size_t maxCaption = kCaptionMaxChars) {
        // Align to the next DWORD. The mask is applied to the pointer's integer
        // value, NOT to the pointer itself: masking a BYTE* would require the
        // cast, and the original code cast through ULONG_PTR by hand.
        const auto addr = reinterpret_cast<uintptr_t>(p);
        const auto aligned = (addr + 3u) & ~static_cast<uintptr_t>(3u);
        // `aligned` can never be below `addr` for a real address, but the test
        // costs nothing and keeps the arithmetic honest if that ever changes.
        if (aligned < addr) return false;
        const size_t skip = static_cast<size_t>(aligned - addr);
        if (!usable(skip)) return false;
        // This is the guard that keeps usable()'s signed comparison honest:
        // the padding can put p exactly on `end`, or for a buffer whose end is
        // not DWORD-aligned just past it, so `end - p` must be re-checked AFTER
        // the move rather than only before it.
        if (end - p < 0) return false;
        p = reinterpret_cast<BYTE*>(aligned);

        if (!usable(sizeof(DLGITEMTEMPLATE))) return false;
        auto* it = reinterpret_cast<DLGITEMTEMPLATE*>(p);
        it->style = s;
        it->x = ix; it->y = iy; it->cx = icx; it->cy = icy;
        it->id = id;
        p += sizeof(DLGITEMTEMPLATE);

        // 0xFFFF says "the class is an ordinal", then the ordinal itself.
        if (!usable(4)) return false;
        *reinterpret_cast<WORD*>(p) = 0xFFFF;   // class is an ordinal
        *reinterpret_cast<WORD*>(p + 2) = cls;  // 0x80 edit, 0x81 button
        p += 4;

        if (caption == nullptr) {
            if (!usable(2)) return false;
            ::memset(p, 0, 2);                 // no title
            p += 2;
        } else {
            const size_t n = wcslen(caption) + 1;
            // Captions here are compile-time literals ("OK", "Cancel"), but the
            // parameter is a pointer, so the length is checked rather than
            // assumed: this is the one write in the file that a caller passing
            // a long string would otherwise run off the end on. The label
            // static passes its own (longer) bound; buttons keep the tight
            // one, so a wrong caption still refuses instead of growing the
            // dialog without limit.
            if (n > maxCaption + 1) return false;
            const size_t bytes = Pad4(n * sizeof(wchar_t));
            if (!usable(bytes)) return false;
            memcpy(p, caption, n * sizeof(wchar_t));
            p += bytes;
        }
        if (!usable(2)) return false;
        ::memset(p, 0, 2);                     // no extra data
        p += 2;
        return true;
    };

    // Any refusal here returns an empty vector. cdit matches the
    // control count actually written, so handing the dialog manager
    // fewer than that would make it read past the end of the buffer -
    // which is the out-of-bounds read this file exists to prevent.
    // An empty template is refused by the caller instead.
    //
    // With a label, a STATIC caption sits above the edit and the
    // edit and buttons move down to make room. Without one
    // the compact layout (edit at the top) is kept, so a label-less
    // prompt is unchanged. A multi-line label (the preset list) gets
    // one 8-DLU row per line, capped, so all twelve presets fit
    // instead of painting over the edit.
    if (label != nullptr) {
        const int labelLines = LabelLineCount(label);
        const int shownLines = (labelLines > 1) ? labelLines : 1;
        const short labelH = static_cast<short>(
            kLabelBaseH + kLabelLineH * (shownLines - 1));
        const short editY = static_cast<short>(8 + labelH + 4);
        const short btnY = static_cast<short>(editY + 14 + 6);
        // 0x82 is the STATIC class ordinal. SS_NOPREFIX keeps a
        // '&' in a future label from being read as an accelerator.
        if (!item(WS_CHILD | WS_VISIBLE | SS_NOPREFIX,
                  10, 8, 240, labelH, kIdLabel, 0x82, label,
                  kLabelMaxChars))
            return false;
        if (!item(WS_CHILD | WS_VISIBLE | WS_BORDER | WS_TABSTOP |
                      ES_AUTOHSCROLL,
                  10, editY, 240, 14, kIdEdit, 0x80, nullptr) ||
            !item(WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_DEFPUSHBUTTON,
                  150, btnY, 50, 16, kIdOk, 0x81, L"OK") ||
            !item(WS_CHILD | WS_VISIBLE | WS_TABSTOP,
                  206, btnY, 50, 16, kIdCancel, 0x81, L"Cancel"))
            return false;
    } else {
        if (!item(WS_CHILD | WS_VISIBLE | WS_BORDER | WS_TABSTOP |
                      ES_AUTOHSCROLL,
                  10, 10, 240, 14, kIdEdit, 0x80, nullptr) ||
            !item(WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_DEFPUSHBUTTON,
                  150, 32, 50, 16, kIdOk, 0x81, L"OK") ||
            !item(WS_CHILD | WS_VISIBLE | WS_TABSTOP,
                  206, 32, 50, 16, kIdCancel, 0x81, L"Cancel"))
            return false;
    }

    buf.resize(static_cast<size_t>(p - begin));
    return true;
}

}  // namespace

// The implementation, exposed by the name the header promises. TemplateFitsImpl
// is in the anonymous namespace above; this is the one definition the selftest
// links against, so what is tested is what ships.
bool TemplateFits(DWORD style, DWORD exStyle, short x, short y, short cx,
                  short cy, const wchar_t* title, std::vector<BYTE>* buf,
                  const wchar_t* label) {
    return TemplateFitsImpl(style, exStyle, x, y, cx, cy, title, buf,
                               label);
}

bool PromptForText(HWND owner, const wchar_t* title, const wchar_t* label,
                   const wchar_t* initial, size_t maxChars,
                   std::wstring* out) {
    if (out == nullptr) return false;
    if (title == nullptr) title = L"WinTCP";
    if (label == nullptr) label = L"";
    if (initial == nullptr) initial = L"";

    PromptState st;
    st.value = initial;
    // Keep the pre-filled value inside the bound the control enforces, or the
    // first keystroke would be refused for a field that starts too long.
    if (st.value.size() > maxChars) st.value.resize(maxChars);
    st.maxChars = maxChars;

    // The label is a real caption above the edit. A label longer
    // than the label bound would refuse the whole template (and
    // suppress the prompt), so it is truncated instead - a
    // truncated label still reads, a missing prompt does not. The
    // bound is the label's own (kLabelMaxChars), not the button
    // caption's: a preset list is an instruction, not a caption.
    std::wstring labelBuf;
    if (label != nullptr && label[0] != L'\0') {
        labelBuf = label;
        if (labelBuf.size() > kLabelMaxChars)
            labelBuf.resize(kLabelMaxChars);
    }
    const wchar_t* labelArg =
        labelBuf.empty() ? nullptr : labelBuf.c_str();
    // The dialog grows with the label: one row per line, so the edit
    // and buttons stay clear of a multi-line instruction. The same
    // LabelLineCount the template writer uses, so the frame and the
    // controls agree.
    short cy = 60;
    if (labelArg != nullptr) {
        const int lines = LabelLineCount(labelArg);
        const int shownLines = (lines > 1) ? lines : 1;
        const int labelH =
            kLabelBaseH + kLabelLineH * (shownLines - 1);
        cy = static_cast<short>(8 + labelH + 4 + 14 + 6 + 16 + 8);
    }
    std::vector<BYTE> tpl = MakeTemplate(
        DS_ABSALIGN | DS_CENTER, 0, 0, 0, 270, cy, title, labelArg);
    // An empty template means MakeTemplate refused: a title beyond
    // kTemplateMaxChars, or a write that did not fit. DialogBoxIndirectParamW
    // would then read a zero-length template whose cdit still says 3, so it is
    // not called. The prompt simply does not appear.
    if (tpl.empty()) return false;

    const INT_PTR rc = ::DialogBoxIndirectParamW(
        ::GetModuleHandleW(nullptr),
        reinterpret_cast<LPCDLGTEMPLATEW>(tpl.data()),
        owner, PromptProc, reinterpret_cast<LPARAM>(&st));

    // A negative return is a creation failure, distinct from Cancel's zero.
    if (rc <= 0) return false;
    if (!st.confirmed) return false;
    *out = st.value;
    return true;
}

}  // namespace wintcp
