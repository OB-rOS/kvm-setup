
pub mod kvm {
    const KVM_CREATE_VM: libc::c_ulong = 0x01;
    const KVM_GET_VCPU_MMAP_SIZE: libc::c_ulong = 0x04;
    const KVM_CREATE_VCPU: libc::c_ulong = 0x41;
    const KVM_SET_USER_MEMORY_REGION: libc::c_ulong = 0x46;
    const KVM_RUN: libc::c_ulong = 0x80;
    const KVM_GET_REGS: libc::c_ulong = 0x81;
    const KVM_SET_REGS: libc::c_ulong = 0x82;
    const KVM_GET_SREGS: libc::c_ulong = 0x83;
    const KVM_SET_SREGS: libc::c_ulong = 0x84;
    ioctl_none!(create_vm, kvm_wrapper::KVMIO, KVM_CREATE_VM);
    ioctl_none!(create_vcpu, kvm_wrapper::KVMIO, KVM_CREATE_VCPU);
    ioctl_none!(get_vcpu_mmap_size, kvm_wrapper::KVMIO, KVM_GET_VCPU_MMAP_SIZE);
    ioctl_none!(run_cpu, kvm_wrapper::KVMIO, KVM_RUN);
    ioctl_read!(get_regs, kvm_wrapper::KVMIO, KVM_GET_REGS, kvm_wrapper::kvm_regs);
    ioctl_read!(get_sregs, kvm_wrapper::KVMIO, KVM_GET_SREGS, kvm_wrapper::kvm_sregs);
    ioctl_write_ptr!(set_regs, kvm_wrapper::KVMIO, KVM_SET_REGS, kvm_wrapper::kvm_regs);
    ioctl_write_ptr!(set_sregs, kvm_wrapper::KVMIO, KVM_SET_SREGS, kvm_wrapper::kvm_sregs);
    ioctl_write_ptr!(set_user_memory_region_vm, kvm_wrapper::KVMIO, KVM_SET_USER_MEMORY_REGION, kvm_memory_region);
    use std::os::unix::io::RawFd;
    use nix::fcntl::OFlag;
    use nix::sys::mman::mmap;
    use nix::sys::mman::ProtFlags;
    use nix::sys::mman::MapFlags;
    use kvm_wrapper::kvm_run;
    use kvm_wrapper::kvm_regs;
    use kvm_wrapper::kvm_sregs;
    use std::ffi::CStr;

    #[repr(C)]
    pub struct kvm_memory_region {
        slot: u32,
        flags: u32,
        guest_phys_address: u64,
        memory_size: u64,
        userspace_addr: u64
    }

    pub fn gen_kvm(code: Vec<libc::uint8_t>) -> u32 {

        let kvmfd: Result<RawFd, nix::Error> = nix::fcntl::open("/dev/kvm", OFlag::O_RDWR|OFlag::O_CLOEXEC, nix::sys::stat::Mode::empty());

        let kvmfd = match kvmfd {
            Ok(fd) => fd,
            Err(_error) => panic!("Error: Failed to open 'dev/kvm"),
        };

        // Create VM
        unsafe {
            let vmfd = match create_vm(kvmfd) {
                Ok(fd) => fd,
                Err(_error) => panic!("Error: Failed to create VM."),
            };

            // Create user memory region
            let mem_size: usize = 0x40000; // size of user memory you want to assign
            let initial_address: *mut libc::c_void = std::ptr::null_mut() as *mut _ as *mut libc::c_void;
            let mem = match mmap(initial_address, mem_size, ProtFlags::PROT_READ| ProtFlags::PROT_WRITE,
                    MapFlags::MAP_SHARED|MapFlags::MAP_ANONYMOUS, -1, 0) {
                Ok(mem) => mem,
                Err(_error) => panic!("Error: Failed to allocate memory for VM.")
            };
            let user_entry: usize = 0x0;
            let mem_rust_address: *mut u8 = mem as *mut u8;
            std::ptr::copy_nonoverlapping(code.as_ptr().add(user_entry), mem_rust_address, code.len());
            let memory_region = &mut kvm_memory_region {slot: 0, flags: 0, guest_phys_address: 0, memory_size: mem_size as u64, userspace_addr: mem as u64};
            set_user_memory_region_vm(vmfd, memory_region).expect("Error: Failed to set user memory region.");

            // Create vCPU
            let vcpufd = create_vcpu(vmfd).expect("Error: Falied to create CPU");
            let run: *mut kvm_run = gen_vcpu(vcpufd, kvmfd, user_entry);

            loop {
                run_cpu(vcpufd).expect("Error: CPU cycle failed.");
                match (*run).exit_reason {
                    kvm_wrapper::KVM_EXIT_HLT => {
                        eprintln!("KVM_EXIT_HLT");
                        return 0;
                    },
                    kvm_wrapper::KVM_EXIT_IO => {
                        let char_offset = (*run).__bindgen_anon_1.io.data_offset as usize;
                        let run_ptr = run as *const i8;
                        let character = CStr::from_ptr(run_ptr.add(char_offset));
                        print!("{}", character.to_str().expect("Failed to convert IO character"));
                        break;
                    },
                    kvm_wrapper::KVM_EXIT_FAIL_ENTRY => {
                        eprintln!("KVM_EXIT_FAIL_ENTRY: hardware_entry_failure_reason = 0x{}", (*run).__bindgen_anon_1.fail_entry.hardware_entry_failure_reason);
                        return 1;
                    },
                    kvm_wrapper::KVM_EXIT_INTERNAL_ERROR => {
                        eprintln!("KVM_EXIT_INTERNAL_ERROR: suberror = 0x{}", (*run).__bindgen_anon_1.internal.suberror);
                        return 1;
                    },
                    kvm_wrapper::KVM_EXIT_SHUTDOWN => {
                        eprintln!("KVM_EXIT_SHUTDOWN");
                        return 1;
                    },
                    _ => {
                        eprintln!("Unhandled reason: {}", (*run).exit_reason);
                        return 1;
                    },
                }
            }
        }
        return 0
    }

    pub unsafe fn gen_vcpu(vcpufd: i32, kvmfd: i32, user_entry: usize) -> *mut kvm_run {
        // Set memory for vCPU
        let vcpu_map_size = get_vcpu_mmap_size(kvmfd).expect("Error: Failed retrieving vCPU mmap size");
        let initial_address: *mut libc::c_void = std::ptr::null_mut() as *mut _ as *mut libc::c_void;
        let run: *mut kvm_run = match mmap(initial_address, vcpu_map_size as usize, ProtFlags::PROT_READ| ProtFlags::PROT_WRITE,
                MapFlags::MAP_SHARED, vcpufd, 0) {
            Ok(mem) => mem as *mut kvm_run,
            Err(_error) => panic!("Error: Failed to allocate memory for VM.")
        };

        // Set up vCPU's registers
        let regs: Box<kvm_regs> = Box::new(Default::default());
        let regs: *mut kvm_regs = Box::into_raw(regs);
        get_regs(vcpufd, regs).expect("Error: Failed to retrieve vCPU registers.");
        (*regs).rip = user_entry as u64;
        (*regs).rsp = 0x200000; // stack address
        (*regs).rflags = 0x2; // in x86 the 0x2 bit should always be set
        set_regs(vcpufd, regs).expect("Error: Failed to set vCPU registers."); // set registers
        drop(Box::from_raw(regs));

        /* special registers include segment registers */
        let sregs: Box<kvm_sregs> = Box::new(Default::default());
        let sregs: *mut kvm_sregs = Box::into_raw(sregs);
        get_sregs(vcpufd, sregs).expect("Error: Failed to retrieve vCPU special registers.");
        (*sregs).cs.base = 0;
        (*sregs).cs.selector = 0; // let base of code segment equal to zero
        set_sregs(vcpufd, sregs).expect("Error: Failed to set vCPU special registers."); // set registers
        drop(Box::from_raw(sregs));
        return run
    }
}
