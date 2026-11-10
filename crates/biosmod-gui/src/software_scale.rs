//! Keep the window's geometry synchronized during native scale transitions.

use slint::platform::{PlatformError, WindowEvent};

/// Apply a native scale factor to a Slint window.
///
/// Example: `synchronize_scale(window, 1.5)` updates the logical scale.
pub fn synchronize_scale(window: &slint::Window, scale: f32) -> Result<(), PlatformError> {
    if !scale.is_finite() || scale <= 0.0 {
        return Err(
            format!("scale factor: expected a finite positive value | received {scale}").into(),
        );
    }
    // Winit can report a new scale before it reports the resized native window.
    // Keep the root geometry within the current surface until that resize arrives.
    let physical = window.size();
    window.dispatch_event_with_result(WindowEvent::ScaleFactorChanged {
        scale_factor: scale,
    })?;
    if physical.width > 0 && physical.height > 0 {
        window.dispatch_event_with_result(WindowEvent::Resized {
            size: physical.to_logical(window.scale_factor()),
        })?;
    }
    Ok(())
}

/// Synchronize scale events before Slint handles them, while preserving the native event.
///
/// Example: `install(window)` registers the workaround before showing a winit window.
pub fn install(window: &slint::Window) {
    use slint::winit_030::{EventResult, WinitWindowAccessor, winit};
    window.on_winit_window_event(|window, event| {
        if let winit::event::WindowEvent::ScaleFactorChanged { scale_factor, .. } = event
            && let Err(error) = synchronize_scale(window, *scale_factor as f32)
        {
            eprintln!("bme-gui: could not synchronize scale transition: {error}");
        }
        // Slint must still process the original event and its native size writer.
        EventResult::Propagate
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui::AppWindow;
    use slint::ComponentHandle;

    #[test]
    fn software_renderer_handles_live_scale_before_native_resize() {
        use i_slint_backend_testing::{TestingBackend, TestingBackendOptions};
        slint::platform::set_platform(Box::new(TestingBackend::new(TestingBackendOptions {
            renderer_name: Some("software".into()),
            ..Default::default()
        })))
        .unwrap();
        let ui = AppWindow::new().unwrap();
        let window = ui.window();
        window.set_size(slint::PhysicalSize::new(1140, 900));
        ui.show().unwrap();
        let before = window.take_snapshot().unwrap();
        assert_eq!((before.width(), before.height()), (1140, 900));
        synchronize_scale(window, 1.5).unwrap();
        let after = window.take_snapshot().unwrap();
        assert_eq!((after.width(), after.height()), (1140, 900));
        assert_eq!(window.scale_factor(), 1.5);
        // Winit receives the original event after the hook, then a later resize.
        window
            .dispatch_event_with_result(WindowEvent::ScaleFactorChanged { scale_factor: 1.5 })
            .unwrap();
        assert_eq!(window.take_snapshot().unwrap().width(), 1140);
        window.set_size(slint::PhysicalSize::new(1200, 960));
        window
            .dispatch_event_with_result(WindowEvent::Resized {
                size: slint::PhysicalSize::new(1200, 960).to_logical(1.5),
            })
            .unwrap();
        let resized = window.take_snapshot().unwrap();
        assert_eq!((resized.width(), resized.height()), (1200, 960));
        synchronize_scale(window, 1.0).unwrap();
        let down = window.take_snapshot().unwrap();
        assert_eq!((down.width(), down.height()), (1200, 960));
        assert_eq!(window.scale_factor(), 1.0);
        window.set_size(slint::PhysicalSize::new(760, 600));
        let minimum = window.take_snapshot().unwrap();
        assert_eq!((minimum.width(), minimum.height()), (760, 600));
        synchronize_scale(window, 1.5).unwrap();
        let minimum_scaled = window.take_snapshot().unwrap();
        assert_eq!(
            (minimum_scaled.width(), minimum_scaled.height()),
            (760, 600)
        );
        synchronize_scale(window, 1.0).unwrap();
        window.set_size(slint::PhysicalSize::new(761, 601));
        for scale in [1.25, 1.75, 1.0] {
            synchronize_scale(window, scale).unwrap();
            let snapshot = window.take_snapshot().unwrap();
            assert_eq!(
                (snapshot.width(), snapshot.height()),
                (761, 601),
                "scale {scale}"
            );
        }
        // A constant override rejects the requested factor; size must use the accepted factor.
        i_slint_core::window::WindowInner::from_pub(window).set_const_scale_factor(1.25);
        synchronize_scale(window, 1.5).unwrap();
        assert_eq!(window.scale_factor(), 1.25);
        let root = i_slint_core::window::WindowInner::from_pub(window)
            .window_item()
            .unwrap();
        let expected = slint::PhysicalSize::new(761, 601).to_logical(1.25);
        assert!((root.as_pin_ref().width().get() - expected.width).abs() < 0.01);
        assert!((root.as_pin_ref().height().get() - expected.height).abs() < 0.01);
        let overridden = window.take_snapshot().unwrap();
        assert_eq!((overridden.width(), overridden.height()), (761, 601));
        for invalid in [0.0, -1.0, f32::NAN, f32::INFINITY] {
            let error = synchronize_scale(window, invalid).unwrap_err().to_string();
            assert!(
                error.contains("finite positive") && error.contains(&invalid.to_string()),
                "scale {invalid}: {error}"
            );
        }
    }
}
