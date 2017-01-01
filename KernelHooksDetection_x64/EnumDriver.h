#pragma once

VOID EnumDriver(PDRIVER_OBJECT pDriverObject);

VOID EnumDriver(PDRIVER_OBJECT pDriverObject)
{
	//总是缺了上一个驱动的信息
	PLDR_DATA_TABLE_ENTRY entry = (PLDR_DATA_TABLE_ENTRY)pDriverObject->DriverSection;
	//先向上枚举一个
	PLDR_DATA_TABLE_ENTRY firstentry = (PLDR_DATA_TABLE_ENTRY)entry->InLoadOrderLinks.Blink;
	DbgPrint("%p\t%p\t%wZ\t", firstentry->DllBase, firstentry->EntryPoint, firstentry->BaseDllName);
	//再向下枚举所有
	entry = (PLDR_DATA_TABLE_ENTRY)pDriverObject->DriverSection;
	firstentry = entry;
	while ((PLDR_DATA_TABLE_ENTRY)entry->InLoadOrderLinks.Flink != firstentry)
	{
		if (entry->EntryPoint>0xFFFFF80000000000)
		{
			DbgPrint("%p\t%p\t%wZ\t", entry->DllBase, entry->EntryPoint, entry->BaseDllName);
		}
		entry = (PLDR_DATA_TABLE_ENTRY)entry->InLoadOrderLinks.Flink;
	}
}

