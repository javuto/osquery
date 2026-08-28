/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <fstream>

#include <boost/algorithm/string.hpp>
#include <boost/algorithm/string/trim.hpp>

#include <osquery/core/core.h>
#include <osquery/core/tables.h>
#include <osquery/events/linux/udev.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>
#include <osquery/tables/system/linux/pci_devices.h>
#include <osquery/utils/conversions/join.h>
#include <osquery/utils/conversions/split.h>
#include <osquery/utils/conversions/tryto.h>

namespace osquery {
namespace tables {

namespace {

const std::string kDrmSysfsPath = "/sys/class/drm";

std::string readSysFile(const std::string& path) {
  std::string content;
  if (!readFile(path, content).ok()) {
    return {};
  }
  boost::trim(content);
  return content;
}

std::string drmCardNameToDevicePath(const std::string& drm_dir,
                                    const std::string& card_name) {
  auto target = drm_dir + "/" + card_name + "/device";
  boost::filesystem::path resolved;
  if (!boost::filesystem::exists(target)) {
    return {};
  }
  try {
    resolved = boost::filesystem::canonical(target);
  } catch (const boost::filesystem::filesystem_error&) {
    return {};
  }
  return resolved.string();
}

void collectVramFromDrm(std::map<std::string, std::uint64_t>& vram_by_slot) {
  std::vector<std::string> drm_entries;
  if (!listDirectoriesInDirectory(kDrmSysfsPath, drm_entries).ok()) {
    return;
  }

  for (const auto& entry : drm_entries) {
    if (entry.find("card") == std::string::npos ||
        entry.find("render") != std::string::npos ||
        entry.find("-") != std::string::npos) {
      continue;
    }

    auto device_path = drmCardNameToDevicePath(kDrmSysfsPath, entry);
    if (device_path.empty()) {
      continue;
    }

    std::string vram;
    auto mem_info_vram_total =
        readSysFile(device_path + "/mem_info_vram_total");
    if (!mem_info_vram_total.empty()) {
      vram = mem_info_vram_total;
    }

    if (vram.empty()) {
      continue;
    }

    auto vram_exp = tryTo<std::uint64_t>(vram, 10);
    if (vram_exp.isError()) {
      continue;
    }

    std::string slot;
    auto slot_path = device_path + "/uevent";
    auto uevent = readSysFile(slot_path);
    for (const auto& line : split(uevent, "\n")) {
      if (line.find("PCI_SLOT_NAME=") == 0) {
        slot = line.substr(strlen("PCI_SLOT_NAME="));
        boost::trim(slot);
        break;
      }
    }

    if (!slot.empty()) {
      vram_by_slot[slot] = vram_exp.take();
    }
  }
}

void enrichVram(Row& row,
                const std::map<std::string, std::uint64_t>& vram_by_slot) {
  auto slot_it = row.find("pci_slot");
  if (slot_it == row.end() || slot_it->second.empty()) {
    return;
  }

  auto vram_it = vram_by_slot.find(slot_it->second);
  if (vram_it != vram_by_slot.end()) {
    row["vram"] = BIGINT(vram_it->second);
  }
}

bool isDisplayControllerClass(const std::string& pci_class_attr) {
  std::string lowered = pci_class_attr;
  boost::algorithm::to_lower(lowered);
  boost::trim(lowered);

  if (lowered.size() < 2) {
    return false;
  }

  std::string class_id;
  switch (lowered.size()) {
  case 5:
    class_id = lowered.substr(0, 1);
    break;
  case 6:
  case 7:
    class_id = lowered.substr(0, 2);
    break;
  default:
    return false;
  }

  return class_id == "03";
}

} // namespace

QueryData genGpuInfo(QueryContext& context) {
  QueryData results;

  auto del_udev = [](udev* u) { udev_unref(u); };
  std::unique_ptr<udev, decltype(del_udev)> udev_handle(udev_new(), del_udev);
  if (udev_handle.get() == nullptr) {
    VLOG(1) << "Could not get udev handle";
    return results;
  }

  auto del_udev_enum = [](udev_enumerate* e) { udev_enumerate_unref(e); };
  std::unique_ptr<udev_enumerate, decltype(del_udev_enum)> enumerate(
      udev_enumerate_new(udev_handle.get()), del_udev_enum);
  if (enumerate.get() == nullptr) {
    VLOG(1) << "Could not get udev_enumerate handle";
    return results;
  }

  std::ifstream raw;
  for (const std::string& pci_ids_path : kPciidsPathList) {
    if (pathExists(pci_ids_path)) {
      raw.open(pci_ids_path);
      if (raw) {
        break;
      }
    }
  }

  std::unique_ptr<PciDB> pcidb;
  if (raw.is_open()) {
    pcidb = std::make_unique<PciDB>(raw);
  } else {
    VLOG(1) << "Unexpected error attempting to read pci.ids at path: "
            << osquery::join(kPciidsPathList, " ");
  }

  std::map<std::string, std::uint64_t> vram_by_slot;
  collectVramFromDrm(vram_by_slot);

  udev_enumerate_add_match_subsystem(enumerate.get(), "pci");
  udev_enumerate_scan_devices(enumerate.get());

  struct udev_list_entry *device_entries, *entry;
  device_entries = udev_enumerate_get_list_entry(enumerate.get());

  std::int32_t device_id = 0;
  udev_list_entry_foreach(entry, device_entries) {
    const char* path = udev_list_entry_get_name(entry);

    std::unique_ptr<udev_device, decltype(&udev_device_unref)> device(
        udev_device_new_from_syspath(udev_handle.get(), path),
        udev_device_unref);
    if (device.get() == nullptr) {
      continue;
    }

    auto pci_class_attr =
        UdevEventPublisher::getValue(device.get(), kPCIClassID);
    if (!isDisplayControllerClass(pci_class_attr)) {
      continue;
    }

    Row r;
    r["device_id"] = "GPU" + std::to_string(device_id++);
    r["pci_slot"] = UdevEventPublisher::getValue(device.get(), kPCIKeySlot);
    r["pci_class_id"] = "0x" + pci_class_attr;
    r["driver"] = UdevEventPublisher::getValue(device.get(), kPCIKeyDriver);

    if (pcidb != nullptr) {
      auto status = extractVendorModelFromPciDBIfPresent(
          r,
          UdevEventPublisher::getValue(device.get(), kPCIKeyID),
          UdevEventPublisher::getValue(device.get(), kPCISubsysID),
          *pcidb);
      if (!status.ok()) {
        VLOG(1) << "Unexpected error extracting GPU PCI info: "
                << status.getMessage();
      }
    }

    auto vendor_db = UdevEventPublisher::getValue(device.get(), kPCIKeyVendor);
    auto model_db = UdevEventPublisher::getValue(device.get(), kPCIKeyModel);
    if (r["vendor"].empty() && !vendor_db.empty()) {
      r["vendor"] = vendor_db;
    }
    if (r["model"].empty() && !model_db.empty()) {
      r["model"] = model_db;
    }

    if (!r["model"].empty()) {
      r["name"] = r["model"];
    }

    enrichVram(r, vram_by_slot);

    results.emplace_back(std::move(r));
  }

  return results;
}

} // namespace tables
} // namespace osquery