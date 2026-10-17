// RowAccessible.h
// SPDX-License-Identifier: Apache-2.0
// per-row accessible names for the main virtual list.
//
// The list and the charts paint via GDI with no MSAA/UIA of their own, so a
// screen reader hears the process names from comctl32's default accessible
// object but no per-row "PID 1234, 8 connections" description. This module
// is the narrow bridge: a delegating IAccessible that answers get_accName /
// get_accDescription for row children from the store and forwards every
// other method - all 26 of them - to the list's own standard accessible
// object, so roles, states, navigation and hit-testing stay exactly what
// comctl32 reports and only the two text properties change.
//
// WHY DELEGATION, not a full implementation: a from-scratch IAccessible for
// a 50k-row virtual list would reimplement selection, focus, scrolling and
// table navigation, and every method reimplemented is a method that can
// disagree with the pixels. Two overridden properties cannot.
//
// Lifetime: MainWindow creates one wrapper per WM_GETOBJECT and hands it to
// LresultFromObject, which AddRefs for the client; the caller Releases its
// own reference immediately. The store pointer is borrowed - the window
// outlives every object it serves - and a null store degrades to pure
// delegation rather than a null dereference.

#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif

#include <windows.h>

#include <oleacc.h>   // IAccessible (declaration only; no link dependency)
#include <string>

#include "Connection.h"
#include "ConnectionStore.h"

namespace wintcp {

// What a screen reader hears for one view row. Built by the pure functions
// below, which is what makes the text testable without COM and without a
// window: the selftest pins these builders, and the wrapper below only
// carries their answers to MSAA.
struct AccessibleRowText {
    std::wstring name;         // "chrome.exe, TCPv4, ESTABLISHED"
    std::wstring description;  // "PID 1234, 8 connections"
};

// One flat (ungrouped) row. 'connectionCount' travels as a parameter rather
// than being re-derived, because the caller (wrapper, probe) already holds
// the store and there is exactly one way to count.
AccessibleRowText FlatRowAccessibleText(const Connection& c,
                                        size_t connectionCount);
// One grouped row: per-process aggregates, not individual connections.
AccessibleRowText GroupRowAccessibleText(const ProcessGroup& g);

// The delegating accessible object. Constructed with the list's standard
// object (takes its own reference) and the store it reads rows from.
class RowAccessible : public IAccessible {
public:
    RowAccessible(IAccessible* standard, const ConnectionStore* store);
    virtual ~RowAccessible();

    RowAccessible(const RowAccessible&) = delete;
    RowAccessible& operator=(const RowAccessible&) = delete;

    // IUnknown
    STDMETHODIMP QueryInterface(REFIID riid, void** ppv) override;
    STDMETHODIMP_(ULONG) AddRef() override;
    STDMETHODIMP_(ULONG) Release() override;
    // IDispatch (all delegated)
    STDMETHODIMP GetTypeInfoCount(UINT* pctinfo) override;
    STDMETHODIMP GetTypeInfo(UINT iTInfo, LCID lcid,
                             ITypeInfo** ppTInfo) override;
    STDMETHODIMP GetIDsOfNames(REFIID riid, LPOLESTR* rgszNames, UINT cNames,
                               LCID lcid, DISPID* rgDispId) override;
    STDMETHODIMP Invoke(DISPID dispIdMember, REFIID riid, LCID lcid,
                        WORD wFlags, DISPPARAMS* pDispParams,
                        VARIANT* pVarResult, EXCEPINFO* pExcepInfo,
                        UINT* puArgErr) override;
    // IAccessible: get_accName / get_accDescription answer rows, the rest
    // is delegated.
    STDMETHODIMP get_accParent(IDispatch** ppdispParent) override;
    STDMETHODIMP get_accChildCount(long* pcountChildren) override;
    STDMETHODIMP get_accChild(VARIANT varChild, IDispatch** ppdispChild) override;
    STDMETHODIMP get_accName(VARIANT varChild, BSTR* pszName) override;
    STDMETHODIMP get_accValue(VARIANT varChild, BSTR* pszValue) override;
    STDMETHODIMP get_accDescription(VARIANT varChild,
                                    BSTR* pszDescription) override;
    STDMETHODIMP get_accRole(VARIANT varChild, VARIANT* pvarRole) override;
    STDMETHODIMP get_accState(VARIANT varChild, VARIANT* pvarState) override;
    STDMETHODIMP get_accHelp(VARIANT varChild, BSTR* pszHelp) override;
    STDMETHODIMP get_accHelpTopic(BSTR* pszHelpFile, VARIANT varChild,
                                  long* pidTopic) override;
    STDMETHODIMP get_accKeyboardShortcut(VARIANT varChild,
                                         BSTR* pszKeyboardShortcut) override;
    STDMETHODIMP get_accFocus(VARIANT* pvarChild) override;
    STDMETHODIMP get_accSelection(VARIANT* pvarChildren) override;
    STDMETHODIMP get_accDefaultAction(VARIANT varChild,
                                      BSTR* pszDefaultAction) override;
    STDMETHODIMP accSelect(long flagsSelect, VARIANT varChild) override;
    STDMETHODIMP accLocation(long* pxLeft, long* pyTop, long* pcxWidth,
                             long* pcyHeight, VARIANT varChild) override;
    STDMETHODIMP accNavigate(long navDir, VARIANT varStart,
                             VARIANT* pvarEndUpAt) override;
    STDMETHODIMP accHitTest(long xLeft, long yTop, VARIANT* pvarChild) override;
    STDMETHODIMP accDoDefaultAction(VARIANT varChild) override;
    STDMETHODIMP put_accName(VARIANT varChild, BSTR szName) override;
    STDMETHODIMP put_accValue(VARIANT varChild, BSTR szValue) override;

private:
    // The 0-based view index for a row child, or -1 for anything else
    // (CHILDID_SELF, the window itself, out-of-range rows, non-I4).
    long RowChild(const VARIANT& varChild) const;
    // Row text for a view index, or false when it names no row (caller
    // delegates on false, so an out-of-range child hears comctl32, not us).
    bool RowText(size_t viewIdx, AccessibleRowText* out) const;

    LONG refs_ = 1;
    IAccessible* standard_ = nullptr;   // owned reference, never null
    const ConnectionStore* store_ = nullptr;   // borrowed, may be null
};

// Serve WM_GETOBJECT for the list window. Returns the LRESULT for the
// message, or 0 when no object could be produced - the caller falls through
// to DefWindowProc on 0, because answering 0 unconditionally would both lie
// ("no object") and bypass comctl32's own answer.
LRESULT ServeListAccessibleObject(HWND list, WPARAM wParam,
                                  const ConnectionStore* store);

}  // namespace wintcp
