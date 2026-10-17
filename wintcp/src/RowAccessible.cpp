// RowAccessible.cpp
// SPDX-License-Identifier: Apache-2.0
// See RowAccessible.h.

#include "RowAccessible.h"

#include <new>        // std::nothrow (the wrapper must not throw)
#include <objbase.h>  // IsEqualIID for QueryInterface
#include <oleacc.h>   // IAccessible declaration (signatures checked at compile)

#include "WinCaps.h"   // DllAvailable: oleacc/oleaut32 are delay-loaded

namespace wintcp {
namespace {

// oleacc entry points, resolved dynamically so this module adds no link
// dependency: on a machine without oleacc.dll there is no accessible object
// to wrap, and the list keeps comctl32's default behaviour rather than
// failing to start. Same shape as QueryDpiForWindow's GetDpiForWindow.
using CreateStdAccessibleObject_t = HRESULT(WINAPI*)(HWND, LONG, REFIID,
                                                     void**);
using LresultFromObject_t = LRESULT(WINAPI*)(REFIID, WPARAM, IUnknown*);

bool ResolveOleAcc(CreateStdAccessibleObject_t* createOut,
                   LresultFromObject_t* resultOut) {
    if (createOut == nullptr || resultOut == nullptr) return false;
    if (!DllAvailable("oleacc.dll") || !DllAvailable("oleaut32.dll"))
        return false;
    HMODULE lib = ::GetModuleHandleW(L"oleacc.dll");
    if (lib == nullptr) lib = ::LoadLibraryW(L"oleacc.dll");
    // Deliberately never freed: a process-lifetime handle, the same class
    // as the sampler the architecture notes already leak on purpose. A
    // FreeLibrary here would race the in-flight accessible object it
    // created on another thread.
    if (lib == nullptr) return false;
    *createOut = reinterpret_cast<CreateStdAccessibleObject_t>(
        ::GetProcAddress(lib, "CreateStdAccessibleObject"));
    *resultOut = reinterpret_cast<LresultFromObject_t>(
        ::GetProcAddress(lib, "LresultFromObject"));
    return *createOut != nullptr && *resultOut != nullptr;
}

}  // namespace

AccessibleRowText FlatRowAccessibleText(const Connection& c,
                                        size_t connectionCount) {
    // Visible strings, not paraphrases: a screen reader must hear the same
    // truth the pixels show. An empty process name is "(unknown)", the one
    // placeholder the change log already uses for the same condition.
    AccessibleRowText t;
    t.name = (c.display.processName.empty() ? std::wstring(L"(unknown)")
                                    : c.display.processName);
    t.name += L", " + c.keys.protoLabel + L", " + c.keys.stateLabel;
    t.description = L"PID " + std::to_wstring(c.identity.pid) + L", " +
                    std::to_wstring(connectionCount) +
                    (connectionCount == 1 ? L" connection" : L" connections");
    return t;
}

AccessibleRowText GroupRowAccessibleText(const ProcessGroup& g) {
    // The group already carries its display name ("PID n" when unknown) and
    // its protocol mix; this only joins them the way a flat row is joined.
    AccessibleRowText t;
    t.name = g.name + L", " +
             ((g.hasTcp && g.hasUdp) ? std::wstring(L"TCP+UDP")
              : g.hasTcp            ? std::wstring(L"TCP")
                                    : std::wstring(L"UDP"));
    t.description = L"PID " + std::to_wstring(g.pid) + L", " +
                    std::to_wstring(g.rowCount) +
                    (g.rowCount == 1 ? L" connection" : L" connections");
    return t;
}

RowAccessible::RowAccessible(IAccessible* standard,
                             const ConnectionStore* store)
    : standard_(standard), store_(store) {
    if (standard_ != nullptr) standard_->AddRef();
}

RowAccessible::~RowAccessible() {
    if (standard_ != nullptr) standard_->Release();
}

STDMETHODIMP RowAccessible::QueryInterface(REFIID riid, void** ppv) {
    if (ppv == nullptr) return E_POINTER;
    *ppv = nullptr;
    if (IsEqualIID(riid, IID_IUnknown) || IsEqualIID(riid, IID_IDispatch) ||
        IsEqualIID(riid, IID_IAccessible)) {
        *ppv = static_cast<IAccessible*>(this);
        AddRef();
        return S_OK;
    }
    return E_NOINTERFACE;
}

STDMETHODIMP_(ULONG) RowAccessible::AddRef() {
    return static_cast<ULONG>(::InterlockedIncrement(&refs_));
}

STDMETHODIMP_(ULONG) RowAccessible::Release() {
    const ULONG n = static_cast<ULONG>(::InterlockedDecrement(&refs_));
    if (n == 0) delete this;
    return n;
}

STDMETHODIMP RowAccessible::GetTypeInfoCount(UINT* pctinfo) {
    return standard_->GetTypeInfoCount(pctinfo);
}

STDMETHODIMP RowAccessible::GetTypeInfo(UINT iTInfo, LCID lcid,
                                        ITypeInfo** ppTInfo) {
    return standard_->GetTypeInfo(iTInfo, lcid, ppTInfo);
}

STDMETHODIMP RowAccessible::GetIDsOfNames(REFIID riid, LPOLESTR* rgszNames,
                                          UINT cNames, LCID lcid,
                                          DISPID* rgDispId) {
    return standard_->GetIDsOfNames(riid, rgszNames, cNames, lcid, rgDispId);
}

STDMETHODIMP RowAccessible::Invoke(DISPID dispIdMember, REFIID riid,
                                   LCID lcid, WORD wFlags,
                                   DISPPARAMS* pDispParams,
                                   VARIANT* pVarResult,
                                   EXCEPINFO* pExcepInfo, UINT* puArgErr) {
    return standard_->Invoke(dispIdMember, riid, lcid, wFlags, pDispParams,
                             pVarResult, pExcepInfo, puArgErr);
}

STDMETHODIMP RowAccessible::get_accParent(IDispatch** ppdispParent) {
    return standard_->get_accParent(ppdispParent);
}

STDMETHODIMP RowAccessible::get_accChildCount(long* pcountChildren) {
    return standard_->get_accChildCount(pcountChildren);
}

STDMETHODIMP RowAccessible::get_accChild(VARIANT varChild,
                                         IDispatch** ppdispChild) {
    return standard_->get_accChild(varChild, ppdispChild);
}

STDMETHODIMP RowAccessible::get_accName(VARIANT varChild, BSTR* pszName) {
    if (pszName == nullptr) return E_INVALIDARG;
    *pszName = nullptr;
    AccessibleRowText t;
    const long row = RowChild(varChild);
    if (row < 0 || !RowText(static_cast<size_t>(row), &t))
        return standard_->get_accName(varChild, pszName);
    *pszName = ::SysAllocString(t.name.c_str());
    return (*pszName != nullptr) ? S_OK : E_OUTOFMEMORY;
}

STDMETHODIMP RowAccessible::get_accValue(VARIANT varChild, BSTR* pszValue) {
    return standard_->get_accValue(varChild, pszValue);
}

STDMETHODIMP RowAccessible::get_accDescription(VARIANT varChild,
                                               BSTR* pszDescription) {
    if (pszDescription == nullptr) return E_INVALIDARG;
    *pszDescription = nullptr;
    AccessibleRowText t;
    const long row = RowChild(varChild);
    if (row < 0 || !RowText(static_cast<size_t>(row), &t))
        return standard_->get_accDescription(varChild, pszDescription);
    *pszDescription = ::SysAllocString(t.description.c_str());
    return (*pszDescription != nullptr) ? S_OK : E_OUTOFMEMORY;
}

STDMETHODIMP RowAccessible::get_accRole(VARIANT varChild, VARIANT* pvarRole) {
    return standard_->get_accRole(varChild, pvarRole);
}

STDMETHODIMP RowAccessible::get_accState(VARIANT varChild,
                                         VARIANT* pvarState) {
    return standard_->get_accState(varChild, pvarState);
}

STDMETHODIMP RowAccessible::get_accHelp(VARIANT varChild, BSTR* pszHelp) {
    return standard_->get_accHelp(varChild, pszHelp);
}

STDMETHODIMP RowAccessible::get_accHelpTopic(BSTR* pszHelpFile,
                                             VARIANT varChild,
                                             long* pidTopic) {
    return standard_->get_accHelpTopic(pszHelpFile, varChild, pidTopic);
}

STDMETHODIMP RowAccessible::get_accKeyboardShortcut(
    VARIANT varChild, BSTR* pszKeyboardShortcut) {
    return standard_->get_accKeyboardShortcut(varChild, pszKeyboardShortcut);
}

STDMETHODIMP RowAccessible::get_accFocus(VARIANT* pvarChild) {
    return standard_->get_accFocus(pvarChild);
}

STDMETHODIMP RowAccessible::get_accSelection(VARIANT* pvarChildren) {
    return standard_->get_accSelection(pvarChildren);
}

STDMETHODIMP RowAccessible::get_accDefaultAction(
    VARIANT varChild, BSTR* pszDefaultAction) {
    return standard_->get_accDefaultAction(varChild, pszDefaultAction);
}

STDMETHODIMP RowAccessible::accSelect(long flagsSelect, VARIANT varChild) {
    return standard_->accSelect(flagsSelect, varChild);
}

STDMETHODIMP RowAccessible::accLocation(long* pxLeft, long* pyTop,
                                        long* pcxWidth, long* pcyHeight,
                                        VARIANT varChild) {
    return standard_->accLocation(pxLeft, pyTop, pcxWidth, pcyHeight,
                                  varChild);
}

STDMETHODIMP RowAccessible::accNavigate(long navDir, VARIANT varStart,
                                        VARIANT* pvarEndUpAt) {
    return standard_->accNavigate(navDir, varStart, pvarEndUpAt);
}

STDMETHODIMP RowAccessible::accHitTest(long xLeft, long yTop,
                                       VARIANT* pvarChild) {
    return standard_->accHitTest(xLeft, yTop, pvarChild);
}

STDMETHODIMP RowAccessible::accDoDefaultAction(VARIANT varChild) {
    return standard_->accDoDefaultAction(varChild);
}

STDMETHODIMP RowAccessible::put_accName(VARIANT varChild, BSTR szName) {
    return standard_->put_accName(varChild, szName);
}

STDMETHODIMP RowAccessible::put_accValue(VARIANT varChild, BSTR szValue) {
    return standard_->put_accValue(varChild, szValue);
}

long RowAccessible::RowChild(const VARIANT& varChild) const {
    // ListView row children are 1-based; anything else (CHILDID_SELF,
    // VT_EMPTY, out-of-range) is not a row we name.
    if (varChild.vt != VT_I4 || varChild.lVal < 1) return -1;
    return varChild.lVal - 1;
}

bool RowAccessible::RowText(size_t viewIdx, AccessibleRowText* out) const {
    if (out == nullptr || store_ == nullptr) return false;
    if (viewIdx >= store_->View().size()) return false;
    // Grouped rows name the aggregate, mirroring the LVN_GETDISPINFO path:
    // the group check comes first for the same reason it does there.
    if (const ProcessGroup* g = store_->ViewGroup(viewIdx)) {
        *out = GroupRowAccessibleText(*g);
        return true;
    }
    const Connection* c = store_->ViewRow(viewIdx);
    if (c == nullptr) return false;
    *out = FlatRowAccessibleText(*c, store_->CountForPid(c->identity.pid));
    return true;
}

LRESULT ServeListAccessibleObject(HWND list, WPARAM wParam,
                                  const ConnectionStore* store) {
    if (list == nullptr) return 0;
    CreateStdAccessibleObject_t createFn = nullptr;
    LresultFromObject_t resultFn = nullptr;
    if (!ResolveOleAcc(&createFn, &resultFn)) return 0;
    IAccessible* standard = nullptr;
    if (createFn(list, OBJID_CLIENT, IID_IAccessible,
                 reinterpret_cast<void**>(&standard)) != S_OK ||
        standard == nullptr)
        return 0;
    RowAccessible* wrap = new (std::nothrow) RowAccessible(standard, store);
    standard->Release();   // the wrapper holds its own reference now
    if (wrap == nullptr) return 0;
    const LRESULT lr = resultFn(IID_IAccessible, wParam, wrap);
    wrap->Release();   // LresultFromObject AddRef'd for the client
    return lr;
}

}  // namespace wintcp
