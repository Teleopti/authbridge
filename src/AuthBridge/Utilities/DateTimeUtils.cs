using System;

namespace AuthBridge.Utilities
{
	public static class DateTimeUtils
	{
		public static DateTime TruncateTo(this DateTime dt, DateTruncate truncateTo)
		{
			switch (truncateTo)
			{
				case DateTruncate.Year:
					return new DateTime(dt.Year, 0, 0);
				case DateTruncate.Month:
					return new DateTime(dt.Year, dt.Month, 0);
				case DateTruncate.Day:
					return new DateTime(dt.Year, dt.Month, dt.Day);
				case DateTruncate.Hour:
					return new DateTime(dt.Year, dt.Month, dt.Day, dt.Hour, 0, 0);
				case DateTruncate.Minute:
					return new DateTime(dt.Year, dt.Month, dt.Day, dt.Hour, dt.Minute, 0);
				default:
					return new DateTime(dt.Year, dt.Month, dt.Day, dt.Hour, dt.Minute, dt.Second);
			}
		}

		public enum DateTruncate
		{
			Year,
			Month,
			Day,
			Hour,
			Minute,
			Second
		}
	}
}