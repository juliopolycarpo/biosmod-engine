; MRC checkpoint breadcrumbs for the MR9A UncoreInitPeim (offline, not booted).
; Applies on top of B01-B06 + B02-B03; see docs/boot-breadcrumbs.md.
;
; Intent: keep the last MRC checkpoint of the current boot in upper-bank CMOS,
; and when an MRC pass dies before it ends, freeze its last checkpoint so the
; next good boot can read it from Linux.
;
; Hook: the checkpoint setter FFE0FE3C calls the port-80 writer FFE4276C from
; one site, FFE0FEA9, with esi = MRC context and edi = the packed checkpoint
; just stored at ctx+22124 (major<<24 | minor<<16 | location). That call is
; redirected to `hook`, which repeats the port write (FFE4276C passes ctx
; byte +22127, the same major, to FFE0BFA0, which is `out dx, al`) and then
; records.
; After the call the caller reloads edi (FFE0FEAF) and zeroes ebx (FFE0FEE0)
; before reading them, so hook may clobber eax, ebx, ecx, edx, edi; it keeps
; esi, ebp and esp.
;
; Space (linked addresses, image base FFDE4DE8, raw offset == RVA):
;   r0  FFE4276C  30 bytes  former port-80 writer; only caller was FFE0FEA9
;   ra  FFE613A2  88 bytes  dead NOP run left by the B01-B06 rewrite
;   rb  FFE61903  53 bytes  dead NOP run left by the B01-B06 rewrite
; ra and rb exist only on top of B01-B06; this patch requires it.
;
; CMOS layout (upper bank, ports 72h/73h, absolute index, matching CmosPei).
; The reviewed CmosPei checksum/default/token range is 40h-46h. PlatformEarlyInit
; enables the upper bank before publishing a PPI required by UncoreInitPeim.
; These are build-specific observations, not a universal reservation of E0-E9.
;   E0     state: A0 | slot<<1 | ended. Any other value = not armed.
;   E1-E4  slot 0, E5-E8 slot 1: the packed checkpoint, little-endian
;          (location[7:0], location[15:8], minor, major).
;   E9     failed-pass count, saturates at FFh. Reset to 0 when arming.
;
; A pass starts at checkpoint B0/00 (bootstrap task 3, FFE41CEC) and ends at
; BF (MRC done) or AF (MRC reset request). If a pass starts while the stored
; state says the previous pass never ended, the active slot is frozen (slot
; bit flips) and the count increments. Nothing is recorded after a pass ends,
; so a good boot's later checkpoints cost one CMOS read and one state write.

bits 32

%define CMOS_IDX    0x72
%define CMOS_DAT    0x73
%define BC_STATE    0xE0
%define BC_SLOT0    0xE1
%define BC_COUNT    0xE9
%define ST_ARMED    0xA0
%define ST_ENDED    1
%define ST_SLOT     2
%define CP_PASS     0xB000          ; major B0, minor 00
%define CP_RESET    0xAF
%define CP_DONE     0xBF

CALL_SITE   equ 0xffe0fea9          ; `call FFE4276C` in FFE0FE3C

section r0 align=1 vstart=0xffe4276c
; arm: state was not armed. bl = armed + ended, count = 0 (falls into wr).
arm:
    mov     bl, ST_ARMED|ST_ENDED
    mov     ax, BC_COUNT
; wr: CMOS[al] = ah. Returns al = ah.
wr:
    out     CMOS_IDX, al
    mov     al, ah
    out     CMOS_DAT, al
    ret
; rd: al = CMOS[al].
rd:
    out     CMOS_IDX, al
    in      al, CMOS_DAT
    ret
; slot_base: al = first index of the active slot for state bl.
slot_base:
    mov     bh, 4                  ; always store the complete 32-bit value
    mov     al, bl
    and     al, ST_SLOT
    add     al, al
    add     al, BC_SLOT0
    ret
    times 30-($-$$) int3

section ra follows=r0 align=1 vstart=0xffe613a2
hook:
    mov     dx, [esi+0x62d]         ; original FFE4276C behaviour, with
    mov     eax, edi                ; FFE0BFA0 (out dx, al) inlined:
    bswap   eax                     ; low byte = major; other bytes are dead
    out     dx, al
    mov     al, BC_STATE            ; bl = state, arming if needed
    call    rd
    mov     bl, al
    and     al, ~(ST_ENDED|ST_SLOT)
    cmp     al, ST_ARMED
    je      .armed
    call    arm
.armed:
    mov     eax, edi
    shr     eax, 16
    cmp     ax, CP_PASS
    jne     .record
    call    pass_start
.record:
    test    bl, ST_ENDED
    jnz     write_state
    call    slot_base
    mov     dl, al
    mov     ecx, edi
.store:
    mov     al, dl
    mov     ah, cl
    call    wr
    inc     edx                     ; indexes E1-E8 cannot carry into DH
    shr     ecx, 8
    dec     bh
    jnz     .store                  ; exactly four bytes, including zero majors
    jmp     end_check               ; al = major
    times 88-($-$$) nop

section rb follows=ra align=1 vstart=0xffe61903
; pass_start: bl = state in/out. Freezes the slot of a pass that never ended.
pass_start:
    test    bl, ST_ENDED
    jnz     .run
    xor     bl, ST_SLOT
    mov     al, BC_COUNT
    call    rd
    inc     al
    jz      .run                    ; saturate at FFh
    mov     ah, al
    mov     al, BC_COUNT
    call    wr
.run:
    and     bl, ~ST_ENDED
    ret
; end_check: al = recorded major. BF and AF end the pass.
end_check:
    cmp     al, CP_DONE
    je      .ended
    cmp     al, CP_RESET
    jne     write_state
.ended:
    or      bl, ST_ENDED
write_state:
    mov     al, BC_STATE
    mov     ah, bl
    jmp     wr
    times 53-($-$$) nop

section site follows=rb align=1 vstart=CALL_SITE
    call    hook
